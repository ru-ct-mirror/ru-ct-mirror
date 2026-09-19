package mirror

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

// A run adds chunk files and never rewrites one, so the files a commit adds are
// exactly the entries it observed. Everything here is derived from those files,
// which is what makes the commit message re-derivable from the commit itself.

// maxMessageBytes is the last line of defence on the size of a commit message.
// With the name caps in place it is unreachable.
const maxMessageBytes = 64 << 10

// firstSeenChunkStep is how often a worker checks the deadline while reading a
// chunk: often enough to stop promptly, rarely enough not to matter.
const firstSeenChunkStep = 256

// ChunkRef is one entries chunk together with the shard it belongs to.
type ChunkRef struct {
	Log   string // "operator/shard"
	Chunk store.Chunk
}

// ShardSummary is what one shard contributed to a run.
type ShardSummary struct {
	Log      string
	Start    uint64 // first index of the shard's added chunks
	End      uint64 // last index, inclusive
	Entries  int    // entries actually read
	Unparsed int    // leaves that could not be summarised
}

// Summary is everything a commit message needs to say about a run.
type Summary struct {
	Shards   []ShardSummary // sorted by Log
	Entries  int
	Unparsed int
	Names    []string        // sorted, unique, as stored
	New      map[string]bool // names the mirror had not seen before this run
	Marked   bool            // false when the first-seen scan did not finish
}

// ChunkRefFromPath interprets a path of the form
// <root>/data/<operator>/<shard>/entries/NNNNNNNN-NNNNNNNN.jsonl.gz.
func ChunkRefFromPath(root, path string) (ChunkRef, error) {
	data, err := filepath.Abs(filepath.Join(root, "data"))
	if err != nil {
		return ChunkRef{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ChunkRef{}, err
	}
	rel, err := filepath.Rel(data, abs)
	if err != nil {
		return ChunkRef{}, fmt.Errorf("%s is not under %s", path, data)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 4 || parts[0] == ".." || parts[2] != "entries" {
		return ChunkRef{}, fmt.Errorf("%s is not a chunk of data/<operator>/<shard>/entries", path)
	}
	c, err := store.ParseChunkPath(abs)
	if err != nil {
		return ChunkRef{}, err
	}
	return ChunkRef{Log: parts[0] + "/" + parts[1], Chunk: c}, nil
}

// AllChunks lists every entries chunk under root/data. It reads the file system
// rather than logs.json on purpose: a shard that has been retired or disabled
// still holds names the mirror has seen, and no command-line filter may narrow
// the set of names a first-seen marker is checked against.
func AllChunks(root string) ([]ChunkRef, error) {
	files, err := filepath.Glob(filepath.Join(root, "data", "*", "*", "entries", "*.jsonl.gz"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := make([]ChunkRef, 0, len(files))
	for _, f := range files {
		ref, err := ChunkRefFromPath(root, f)
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

// Summarise reads the given chunks and reports what they added. A leaf that
// cannot be summarised is counted and skipped: a single odd certificate must
// not cost the whole message. A chunk that cannot be read at all is an error,
// because silently dropping it would misreport the run.
func Summarise(refs []ChunkRef) (*Summary, error) {
	s := &Summary{New: map[string]bool{}}
	names := map[string]bool{}
	shards := map[string]*ShardSummary{}
	for _, ref := range dedupe(refs) {
		sh := shards[ref.Log]
		if sh == nil {
			sh = &ShardSummary{Log: ref.Log, Start: ref.Chunk.Start, End: ref.Chunk.End}
			shards[ref.Log] = sh
		}
		if ref.Chunk.Start < sh.Start {
			sh.Start = ref.Chunk.Start
		}
		if ref.Chunk.End > sh.End {
			sh.End = ref.Chunk.End
		}
		err := store.ReadChunk(ref.Chunk, func(e store.Entry) error {
			sh.Entries++
			s.Entries++
			info, ok, err := ParseLeaf(e)
			if err != nil || !ok {
				sh.Unparsed++
				s.Unparsed++
				return nil
			}
			for _, n := range info.Names {
				names[n] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, sh := range shards {
		s.Shards = append(s.Shards, *sh)
	}
	sort.Slice(s.Shards, func(i, j int) bool { return s.Shards[i].Log < s.Shards[j].Log })
	s.Names = make([]string, 0, len(names))
	for n := range names {
		s.Names = append(s.Names, n)
	}
	sort.Strings(s.Names)
	return s, nil
}

// MarkFirstSeen fills s.New by reading every chunk under root that is not one of
// refs, dropping a candidate as soon as it turns up. It reports done=false when
// ctx expired first; s.New is then incomplete and the caller must leave s.Marked
// false rather than emit markers that are only true for part of the mirror.
func MarkFirstSeen(ctx context.Context, s *Summary, root string, refs []ChunkRef, workers int) (bool, error) {
	s.New = map[string]bool{}
	if len(s.Names) == 0 {
		return true, nil
	}
	all, err := AllChunks(root)
	if err != nil {
		return false, err
	}
	own := map[string]bool{}
	for _, ref := range refs {
		own[ref.Chunk.Path] = true
	}
	var older []ChunkRef
	for _, ref := range all {
		if !own[ref.Chunk.Path] {
			older = append(older, ref)
		}
	}
	// Newest first: a name that is not new is usually a renewal, and renewals
	// are found in the chunks nearest the tip.
	sort.Slice(older, func(i, j int) bool { return older[i].Chunk.Start > older[j].Chunk.Start })

	candidates := map[string]bool{}
	for _, n := range s.Names {
		candidates[n] = true
	}
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}
	// A private cancel lets the workers stop the moment nothing is left to look
	// for, without that being mistaken for the deadline expiring.
	inner, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan ChunkRef)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ref := range work {
				if inner.Err() != nil {
					return
				}
				n := 0
				err := store.ReadChunk(ref.Chunk, func(e store.Entry) error {
					n++
					if n%firstSeenChunkStep == 0 && inner.Err() != nil {
						return inner.Err()
					}
					info, ok, err := ParseLeaf(e)
					if err != nil || !ok {
						return nil
					}
					mu.Lock()
					for _, name := range info.Names {
						delete(candidates, name)
					}
					empty := len(candidates) == 0
					mu.Unlock()
					if empty {
						cancel()
						return inner.Err()
					}
					return nil
				})
				if err != nil && inner.Err() == nil {
					errs <- fmt.Errorf("%s: %w", ref.Chunk.Path, err)
					// Stop the others and, above all, release the sender: a
					// worker that leaves without this would strand the loop
					// below on a channel nobody is reading any more.
					cancel()
					return
				}
			}
		}()
	}
	for _, ref := range older {
		if inner.Err() != nil {
			break
		}
		select {
		case work <- ref:
		case <-inner.Done():
		}
	}
	close(work)
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return false, err
	}
	if ctx.Err() != nil {
		return false, nil
	}
	mu.Lock()
	defer mu.Unlock()
	for n := range candidates {
		s.New[n] = true
	}
	return true, nil
}

func dedupe(refs []ChunkRef) []ChunkRef {
	seen := map[string]bool{}
	out := make([]ChunkRef, 0, len(refs))
	for _, ref := range refs {
		if seen[ref.Chunk.Path] {
			continue
		}
		seen[ref.Chunk.Path] = true
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Log != out[j].Log {
			return out[i].Log < out[j].Log
		}
		return out[i].Chunk.Start < out[j].Chunk.Start
	})
	return out
}

// Render writes the commit message for s: a subject that stays parsable as
// "sync <timestamp>", then the shards, then the names.
func (s *Summary) Render(w io.Writer, now time.Time, maxNames int) error {
	var b bytes.Buffer
	newCount := 0
	for _, n := range s.Names {
		if s.New[n] {
			newCount++
		}
	}
	fmt.Fprintf(&b, "sync %s: %s, %s", now.UTC().Format(time.RFC3339),
		plural(s.Entries, "entry", "entries"), plural(len(s.Names), "name", "names"))
	if s.Marked && len(s.Names) > 0 {
		fmt.Fprintf(&b, " (%d new)", newCount)
	}
	b.WriteString("\n")

	if len(s.Shards) == 0 {
		b.WriteString("\nNo entries chunks were added by this run. The commit records new STHs,\nstate.json updates or a ctlog.json snapshot only.\n")
		return write(w, &b)
	}

	width := 0
	for _, sh := range s.Shards {
		if len(sh.Log) > width {
			width = len(sh.Log)
		}
	}
	b.WriteString("\n")
	for _, sh := range s.Shards {
		fmt.Fprintf(&b, "%-*s  [%d, %d]  %s\n", width, sh.Log, sh.Start, sh.End,
			plural(sh.Entries, "entry", "entries"))
	}

	b.WriteString("\n")
	if s.Unparsed > 0 {
		fmt.Fprintf(&b, "%s could not be parsed and are not in the list below.\n\n",
			plural(s.Unparsed, "leaf", "leaves"))
	}
	if !s.Marked {
		b.WriteString("The first-seen scan did not finish, so the + markers are omitted.\n\n")
	}
	if len(s.Names) == 0 {
		b.WriteString("The added entries carry no DNS names.\n")
		return write(w, &b)
	}
	if s.Marked {
		b.WriteString("Names in the added chunks, + when new to this mirror:\n\n")
	} else {
		b.WriteString("Names in the added chunks:\n\n")
	}
	for i, n := range s.Names {
		if maxNames > 0 && i >= maxNames {
			fmt.Fprintf(&b, "… and %d more names in the added chunks\n", len(s.Names)-i)
			break
		}
		mark := "  "
		if s.Marked && s.New[n] {
			mark = "+ "
		}
		d := DisplayName(n)
		if d == "" {
			continue
		}
		b.WriteString(mark + d + "\n")
	}
	return write(w, &b)
}

func write(w io.Writer, b *bytes.Buffer) error {
	out := b.Bytes()
	if len(out) > maxMessageBytes {
		cut := bytes.LastIndexByte(out[:maxMessageBytes], '\n')
		if cut < 0 {
			cut = maxMessageBytes
		}
		out = append(append([]byte{}, out[:cut+1]...), "… (message truncated)\n"...)
	}
	_, err := w.Write(out)
	return err
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

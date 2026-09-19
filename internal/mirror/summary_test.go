package mirror

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

var (
	testExpiry = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	testNow    = time.Date(2026, 9, 19, 18, 23, 7, 0, time.UTC)
)

// summarise runs what the summary subcommand runs: read the run's chunks, then
// decide which of their names the mirror had not seen before.
func summarise(t *testing.T, root string, refs ...ChunkRef) *Summary {
	t.Helper()
	s, err := Summarise(refs)
	if err != nil {
		t.Fatal(err)
	}
	done, err := MarkFirstSeen(context.Background(), s, root, refs, 2)
	if err != nil {
		t.Fatal(err)
	}
	s.Marked = done
	return s
}

func render(t *testing.T, s *Summary) string {
	t.Helper()
	var b bytes.Buffer
	if err := s.Render(&b, testNow, 100); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestSummariseRangesAndCounts(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	a := writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "one.example.ru", []string{"one.example.ru"}, testExpiry),
		ca.leaf(t, "two.example.ru", []string{"two.example.ru", "one.example.ru"}, testExpiry),
	})
	b := writeTestChunk(t, root, "yandex/2026", 7, [][]byte{
		ca.leaf(t, "three.example.ru", []string{"three.example.ru"}, testExpiry),
	})

	s := summarise(t, root, b, a) // order of the arguments must not matter
	if s.Entries != 3 || s.Unparsed != 0 {
		t.Fatalf("entries=%d unparsed=%d", s.Entries, s.Unparsed)
	}
	want := []string{"one.example.ru", "three.example.ru", "two.example.ru"}
	if strings.Join(s.Names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", s.Names, want)
	}
	if len(s.Shards) != 2 || s.Shards[0].Log != "vk/2026" || s.Shards[1].Log != "yandex/2026" {
		t.Fatalf("shards = %+v", s.Shards)
	}
	if s.Shards[0].Start != 0 || s.Shards[0].End != 1 || s.Shards[0].Entries != 2 {
		t.Fatalf("vk shard = %+v", s.Shards[0])
	}
	if s.Shards[1].Start != 7 || s.Shards[1].End != 7 || s.Shards[1].Entries != 1 {
		t.Fatalf("yandex shard = %+v", s.Shards[1])
	}
	for _, n := range s.Names {
		if !s.New[n] {
			t.Fatalf("%s should be new: the mirror holds nothing else", n)
		}
	}
}

func TestFirstSeenAcrossShards(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	// vk already holds a.ru from an earlier run; this run adds a chunk to
	// yandex that carries a.ru again plus b.ru.
	writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "a.ru", []string{"a.ru"}, testExpiry),
	})
	now := writeTestChunk(t, root, "yandex/2026", 0, [][]byte{
		ca.leaf(t, "a.ru", []string{"a.ru", "b.ru"}, testExpiry),
	})

	s := summarise(t, root, now)
	if !s.Marked {
		t.Fatal("the scan should have finished")
	}
	if s.New["a.ru"] {
		t.Fatal("a.ru is already in the mirror, in another shard")
	}
	if !s.New["b.ru"] {
		t.Fatal("b.ru is new")
	}
	msg := render(t, s)
	if !strings.Contains(msg, "\n+ b.ru\n") || !strings.Contains(msg, "\n  a.ru\n") {
		t.Fatalf("markers wrong:\n%s", msg)
	}
	if !strings.Contains(msg, "2 names (1 new)") {
		t.Fatalf("subject wrong:\n%s", msg)
	}
}

func TestPrecertAndCertForSameNameInOneRun(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	pre := writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.precertLeaf(t, "a.ru", []string{"a.ru"}, testExpiry),
	})
	crt := writeTestChunk(t, root, "vk/2026", 1, [][]byte{
		ca.leaf(t, "a.ru", []string{"a.ru"}, testExpiry),
	})

	s := summarise(t, root, pre, crt)
	if len(s.Names) != 1 || s.Names[0] != "a.ru" {
		t.Fatalf("names = %v", s.Names)
	}
	if !s.New["a.ru"] {
		t.Fatal("the precertificate of the same run must not make its certificate old news")
	}
	if s.Shards[0].Start != 0 || s.Shards[0].End != 1 || s.Shards[0].Entries != 2 {
		t.Fatalf("shard = %+v", s.Shards[0])
	}
	if n := strings.Count(render(t, s), "a.ru"); n != 1 {
		t.Fatalf("name listed %d times", n)
	}
}

func TestNewWithinTheSameRun(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	// The same certificate is logged to two shards in one run: still new.
	one := writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "a.ru", []string{"a.ru"}, testExpiry),
	})
	two := writeTestChunk(t, root, "yandex/2026", 0, [][]byte{
		ca.leaf(t, "a.ru", []string{"a.ru"}, testExpiry),
	})
	s := summarise(t, root, one, two)
	if !s.New["a.ru"] {
		t.Fatal("a name added by this run to two shards is new to the mirror")
	}
}

func TestNoNewEntries(t *testing.T) {
	s := summarise(t, t.TempDir())
	if s.Entries != 0 || len(s.Names) != 0 || len(s.Shards) != 0 {
		t.Fatalf("summary = %+v", s)
	}
	msg := render(t, s)
	if !strings.HasPrefix(msg, "sync 2026-09-19T18:23:07Z: 0 entries, 0 names\n") {
		t.Fatalf("subject wrong:\n%s", msg)
	}
	if !strings.Contains(msg, "No entries chunks were added by this run.") {
		t.Fatalf("body wrong:\n%s", msg)
	}
}

func TestUnparseableLeafIsCountedNotNamed(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	garbageCert, err := tls.Marshal(ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: uint64(testNow.UnixMilli()),
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: []byte("not a certificate")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "a.ru", []string{"a.ru"}, testExpiry),
		garbageCert,
		[]byte("not a leaf either"),
	})

	s := summarise(t, root, ref)
	if s.Entries != 3 || s.Unparsed != 2 {
		t.Fatalf("entries=%d unparsed=%d", s.Entries, s.Unparsed)
	}
	if len(s.Names) != 1 || s.Names[0] != "a.ru" {
		t.Fatalf("names = %v", s.Names)
	}
	if msg := render(t, s); !strings.Contains(msg, "2 leaves could not be parsed") {
		t.Fatalf("body does not own up to the skipped leaves:\n%s", msg)
	}
}

func TestMarkFirstSeenDeadlineOmitsAllMarkers(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "old.ru", []string{"old.ru"}, testExpiry),
	})
	ref := writeTestChunk(t, root, "yandex/2026", 0, [][]byte{
		ca.leaf(t, "old.ru", []string{"old.ru", "new.ru"}, testExpiry),
	})
	s, err := Summarise([]ChunkRef{ref})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done, err := MarkFirstSeen(ctx, s, root, []ChunkRef{ref}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Fatal("a cancelled scan must not report itself finished")
	}
	s.Marked = done
	msg := render(t, s)
	for _, line := range strings.Split(msg, "\n") {
		if strings.HasPrefix(line, "+ ") {
			t.Fatalf("partial markers leaked into the message:\n%s", msg)
		}
	}
	if strings.Contains(msg, " new)") {
		t.Fatalf("the subject counts names it could not check:\n%s", msg)
	}
	if !strings.Contains(msg, "first-seen scan did not finish") {
		t.Fatalf("body does not explain the missing markers:\n%s", msg)
	}
	for _, n := range []string{"new.ru", "old.ru"} {
		if !strings.Contains(msg, "\n  "+n+"\n") {
			t.Fatalf("%s missing from an unmarked list:\n%s", n, msg)
		}
	}
}

func TestRenderCapsNamesAndIsDeterministic(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	var sans []string
	for i := 0; i < 120; i++ {
		sans = append(sans, fmt.Sprintf("host%03d.example.ru", i))
	}
	ref := writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "host000.example.ru", sans, testExpiry),
	})
	s := summarise(t, root, ref)
	first := render(t, s)
	if first != render(t, s) {
		t.Fatal("two renderings of one summary differ")
	}
	if !strings.Contains(first, "… and 20 more names in the added chunks") {
		t.Fatalf("list not capped:\n%s", first)
	}
	if n := strings.Count(first, "+ host"); n != 100 {
		t.Fatalf("listed %d names, want 100", n)
	}
	if strings.Contains(first, "host100.example.ru") {
		t.Fatal("a name beyond the cap was listed")
	}
}

func TestRenderSubjectStaysGrepable(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	ref := writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "sync.example.ru", []string{"sync.example.ru", "sync 2026.example.ru"}, testExpiry),
	})
	msg := render(t, summarise(t, root, ref))
	re := regexp.MustCompile(`(?m)^sync [0-9]`)
	if n := len(re.FindAllString(msg, -1)); n != 1 {
		t.Fatalf("subject regexp matches %d lines:\n%s", n, msg)
	}
	for _, line := range strings.Split(msg, "\n") {
		if strings.HasPrefix(line, "sync ") && !strings.HasPrefix(line, "sync 2026-09-19") {
			t.Fatalf("a name reached column 0 of its own line: %q", line)
		}
	}
}

func TestChunkRefFromPath(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	ref := writeTestChunk(t, root, "vk/2026", 2048, [][]byte{
		ca.leaf(t, "a.ru", []string{"a.ru"}, testExpiry),
	})
	if ref.Log != "vk/2026" || ref.Chunk.Start != 2048 || ref.Chunk.End != 2048 {
		t.Fatalf("ref = %+v", ref)
	}
	for _, p := range []string{
		filepath.Join(root, "logs.json"),
		filepath.Join(root, "data", "vk", "2026", "state.json"),
		filepath.Join(root, "data", "vk", "entries", "00000000-00000000.jsonl.gz"),
		"/etc/hosts",
		filepath.Join(root, "data", "vk", "2026", "entries", "00000000-00000000.jsonl.gz.tmp"),
	} {
		if _, err := ChunkRefFromPath(root, p); err == nil {
			t.Fatalf("%s was accepted as a chunk", p)
		}
	}
}

func TestMarkFirstSeenReportsAnUnreadableChunk(t *testing.T) {
	root, ca := t.TempDir(), newTestCA(t)
	// Two chunks the scan has to get through, the newer one corrupt, and a
	// single worker: the worker gives up on the corrupt chunk while the other
	// is still queued.
	old := writeTestChunk(t, root, "vk/2026", 0, [][]byte{
		ca.leaf(t, "old.ru", []string{"old.ru"}, testExpiry),
	})
	broken := writeTestChunk(t, root, "vk/2026", 1, [][]byte{
		ca.leaf(t, "broken.ru", []string{"broken.ru"}, testExpiry),
	})
	f, err := os.OpenFile(broken.Chunk.Path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("garbage"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	_ = old

	ref := writeTestChunk(t, root, "yandex/2026", 0, [][]byte{
		ca.leaf(t, "new.ru", []string{"new.ru"}, testExpiry),
	})
	s, err := Summarise([]ChunkRef{ref})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		done bool
		err  error
	}
	res := make(chan result, 1)
	go func() {
		done, err := MarkFirstSeen(context.Background(), s, root, []ChunkRef{ref}, 1)
		res <- result{done, err}
	}()
	select {
	case got := <-res:
		if got.err == nil {
			t.Fatalf("a corrupt chunk went unreported: done=%v", got.done)
		}
		if got.done {
			t.Fatal("a scan that could not read the mirror must not report itself finished")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("MarkFirstSeen did not return: the dispatcher is stuck on a channel no worker is reading")
	}
}

// Package store is the on-disk layout of one mirrored shard:
//
//	<dir>/state.json                     last verified tree size and root
//	<dir>/sth.jsonl                      every distinct STH observed, append-only
//	<dir>/entries/NNNNNNNN-NNNNNNNN.jsonl.gz  immutable chunks of entries
//	<dir>/alerts/<timestamp>-<kind>.json  written only when verification fails
package store

import (
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

// State is the content of state.json.
type State struct {
	TreeSize     uint64 `json:"tree_size"`
	RootHash     string `json:"root_hash"`
	STHTimestamp uint64 `json:"sth_timestamp"`
	// Updated is when the verified tree last changed, not when it was last checked.
	Updated string `json:"updated"`
}

// STHRecord is one line of sth.jsonl: the raw get-sth response plus when we saw it.
type STHRecord struct {
	Observed string            `json:"observed"`
	STH      ct.GetSTHResponse `json:"sth"`
}

// Entry is one line of an entries chunk.
type Entry struct {
	Index     uint64 `json:"index"`
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

// Chunk describes one entries file.
type Chunk struct {
	Path  string
	Start uint64 // first index, inclusive
	End   uint64 // last index, inclusive
}

// Store is one shard directory.
type Store struct {
	Dir string
}

// Open ensures the directory exists.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o755); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// LoadState returns the saved state. found is false when the shard has never
// completed a verified sync; the returned state is then zero.
func (s *Store) LoadState() (st State, found bool, err error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "state.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, false, fmt.Errorf("state.json: %w", err)
	}
	return st, true, nil
}

// SaveState writes state.json atomically.
func (s *Store) SaveState(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, "state.json"), append(b, '\n'))
}

// LastSTH returns the most recently recorded STH, or nil.
func (s *Store) LastSTH() (*STHRecord, error) {
	f, err := os.Open(filepath.Join(s.Dir, "sth.jsonl"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var last *STHRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var r STHRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("sth.jsonl: %w", err)
		}
		last = &r
	}
	return last, sc.Err()
}

// AppendSTH records an STH unless it equals the last recorded one.
// It returns true when a line was written.
func (s *Store) AppendSTH(raw ct.GetSTHResponse, observed time.Time) (bool, error) {
	last, err := s.LastSTH()
	if err != nil {
		return false, err
	}
	if last != nil && last.STH.TreeSize == raw.TreeSize && string(last.STH.SHA256RootHash) == string(raw.SHA256RootHash) {
		return false, nil
	}
	line, err := json.Marshal(STHRecord{Observed: observed.UTC().Format(time.RFC3339), STH: raw})
	if err != nil {
		return false, err
	}
	return true, appendLine(filepath.Join(s.Dir, "sth.jsonl"), line)
}

// Chunks lists entry chunks sorted by start index.
func (s *Store) Chunks() ([]Chunk, error) {
	files, err := filepath.Glob(filepath.Join(s.Dir, "entries", "*.jsonl.gz"))
	if err != nil {
		return nil, err
	}
	var out []Chunk
	for _, f := range files {
		var c Chunk
		if _, err := fmt.Sscanf(filepath.Base(f), "%08d-%08d.jsonl.gz", &c.Start, &c.End); err != nil {
			return nil, fmt.Errorf("unexpected chunk file name %s", f)
		}
		c.Path = f
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// WriteChunk stores entries with consecutive indexes starting at start.
// The file must not exist yet.
func (s *Store) WriteChunk(start uint64, entries []ct.LeafEntry) (Chunk, error) {
	if len(entries) == 0 {
		return Chunk{}, errors.New("empty chunk")
	}
	c := Chunk{Start: start, End: start + uint64(len(entries)) - 1}
	c.Path = filepath.Join(s.Dir, "entries", fmt.Sprintf("%08d-%08d.jsonl.gz", c.Start, c.End))
	if _, err := os.Stat(c.Path); err == nil {
		return c, fmt.Errorf("chunk %s already exists", c.Path)
	}
	tmp := c.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return c, err
	}
	gz, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	w := bufio.NewWriter(gz)
	enc := json.NewEncoder(w)
	for i, e := range entries {
		if err := enc.Encode(Entry{Index: start + uint64(i), LeafInput: e.LeafInput, ExtraData: e.ExtraData}); err != nil {
			f.Close()
			os.Remove(tmp)
			return c, err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return c, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return c, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return c, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return c, err
	}
	return c, os.Rename(tmp, c.Path)
}

// ForEachEntry streams all stored entries in index order and checks that they
// form the contiguous range [0, n). It returns n.
func (s *Store) ForEachEntry(fn func(Entry) error) (uint64, error) {
	chunks, err := s.Chunks()
	if err != nil {
		return 0, err
	}
	var next uint64
	for _, c := range chunks {
		if c.Start != next {
			return next, fmt.Errorf("gap in entries: expected chunk starting at %d, found %s", next, filepath.Base(c.Path))
		}
		if err := readChunk(c, func(e Entry) error {
			if e.Index != next {
				return fmt.Errorf("%s: expected index %d, found %d", filepath.Base(c.Path), next, e.Index)
			}
			next++
			return fn(e)
		}); err != nil {
			return next, err
		}
		if next != c.End+1 {
			return next, fmt.Errorf("%s: ends at %d, name promises %d", filepath.Base(c.Path), next-1, c.End)
		}
	}
	return next, nil
}

func readChunk(c Chunk, fn func(Entry) error) error {
	f, err := os.Open(c.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", c.Path, err)
	}
	// Decode until an explicit io.EOF: json.Decoder.More reports false on any
	// reader error too, which would hide a corrupt or truncated gzip trailer.
	dec := json.NewDecoder(bufio.NewReaderSize(gz, 1<<20))
	for {
		var e Entry
		err := dec.Decode(&e)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", c.Path, err)
		}
		if err := fn(e); err != nil {
			return err
		}
	}
}

// PruneBeyond deletes chunks that start at or after verified, i.e. data left
// behind by a run that was interrupted before state.json was updated. It
// returns the removed paths.
func (s *Store) PruneBeyond(verified uint64) ([]string, error) {
	chunks, err := s.Chunks()
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, c := range chunks {
		if c.Start >= verified {
			if err := os.Remove(c.Path); err != nil {
				return removed, err
			}
			removed = append(removed, c.Path)
		}
	}
	return removed, nil
}

// WriteAlert stores a verification failure as evidence and returns its path.
func (s *Store) WriteAlert(kind string, payload any, now time.Time) (string, error) {
	dir := filepath.Join(s.Dir, "alerts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, fmt.Sprintf("%s-%s.json", now.UTC().Format("20060102T150405Z"), kind))
	return p, writeAtomic(p, append(b, '\n'))
}

// Quarantine moves a chunk that failed verification into alerts/ so the served
// data is kept as evidence without polluting the verified entry sequence.
func (s *Store) Quarantine(c Chunk, now time.Time) (string, error) {
	dir := filepath.Join(s.Dir, "alerts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, now.UTC().Format("20060102T150405Z")+"-"+filepath.Base(c.Path))
	return dst, os.Rename(c.Path, dst)
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func appendLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// B64 is a small helper for messages.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

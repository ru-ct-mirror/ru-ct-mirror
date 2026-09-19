package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

func TestChunkRoundTripAndContiguity(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(n int, from byte) []ct.LeafEntry {
		out := make([]ct.LeafEntry, n)
		for i := range out {
			out[i] = ct.LeafEntry{LeafInput: []byte{from + byte(i)}, ExtraData: []byte("x")}
		}
		return out
	}
	if _, err := s.WriteChunk(0, mk(3, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(3, mk(2, 3)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(0, mk(3, 0)); err == nil {
		t.Fatal("overwriting an existing chunk must fail")
	}
	var got []byte
	n, err := s.ForEachEntry(func(e Entry) error { got = append(got, e.LeafInput[0]); return nil })
	if err != nil || n != 5 || string(got) != "\x00\x01\x02\x03\x04" {
		t.Fatalf("n=%d got=%v err=%v", n, got, err)
	}
	// A gap must be detected.
	if _, err := s.WriteChunk(7, mk(1, 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ForEachEntry(func(Entry) error { return nil }); err == nil {
		t.Fatal("gap not detected")
	}
}

func TestAppendSTHDedups(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := ct.GetSTHResponse{TreeSize: 1, Timestamp: 1, SHA256RootHash: []byte("r1"), TreeHeadSignature: []byte("s")}
	b := a
	b.Timestamp = 2 // same tree, fresher signature: not worth a new line
	c := a
	c.SHA256RootHash = []byte("r2") // same size, different root: must be recorded
	now := time.Unix(0, 0)
	for i, tc := range []struct {
		sth  ct.GetSTHResponse
		want bool
	}{{a, true}, {a, false}, {b, false}, {c, true}, {a, true}} {
		got, err := s.AppendSTH(tc.sth, now)
		if err != nil || got != tc.want {
			t.Fatalf("case %d: got %v err %v, want %v", i, got, err, tc.want)
		}
	}
	last, err := s.LastSTH()
	if err != nil || last == nil || string(last.STH.SHA256RootHash) != "r1" {
		t.Fatalf("last=%+v err=%v", last, err)
	}
}

func TestStateAndAlert(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, found, err := s.LoadState()
	if err != nil || found || st.TreeSize != 0 {
		t.Fatalf("empty state: %+v %v", st, err)
	}
	if err := s.SaveState(State{TreeSize: 7, RootHash: "abc"}); err != nil {
		t.Fatal(err)
	}
	st, _, _ = s.LoadState()
	if st.TreeSize != 7 || st.RootHash != "abc" {
		t.Fatalf("state round trip: %+v", st)
	}
	p, err := s.WriteAlert("test", map[string]any{"k": "v"}, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "20260102T030405Z-test.json" {
		t.Fatalf("alert name %s", p)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedGzipTrailerIsAnError(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.WriteChunk(0, []ct.LeafEntry{{LeafInput: []byte("a")}, {LeafInput: []byte("b")}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(c.Path)
	// Strip the 8-byte gzip trailer (CRC32 + ISIZE): every record is still
	// readable, only the integrity check is gone.
	os.WriteFile(c.Path, b[:len(b)-8], 0o644)
	n, err := s.ForEachEntry(func(Entry) error { return nil })
	if err == nil {
		t.Fatalf("truncated trailer went unnoticed after %d entries", n)
	}
	// Flip a byte in the middle: CRC mismatch must surface too.
	b2 := append([]byte(nil), b...)
	b2[len(b2)-12] ^= 0xff
	os.WriteFile(c.Path, b2, 0o644)
	if _, err := s.ForEachEntry(func(Entry) error { return nil }); err == nil {
		t.Fatal("corrupted gzip body went unnoticed")
	}
}

func TestPruneBeyond(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := []ct.LeafEntry{{LeafInput: []byte("a")}}
	s.WriteChunk(0, e)
	s.WriteChunk(1, e)
	s.WriteChunk(2, e)
	removed, err := s.PruneBeyond(2)
	if err != nil || len(removed) != 1 {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	chunks, _ := s.Chunks()
	if len(chunks) != 2 || chunks[1].End != 1 {
		t.Fatalf("chunks after prune: %+v", chunks)
	}
}

func TestReadChunkReadsOnlyThatChunk(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(0, []ct.LeafEntry{{LeafInput: []byte{0}}, {LeafInput: []byte{1}}}); err != nil {
		t.Fatal(err)
	}
	second, err := s.WriteChunk(2, []ct.LeafEntry{{LeafInput: []byte{2}}})
	if err != nil {
		t.Fatal(err)
	}
	var got []uint64
	if err := ReadChunk(second, func(e Entry) error { got = append(got, e.Index); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("got %v, want just entry 2", got)
	}
	missing := Chunk{Path: filepath.Join(s.Dir, "entries", "00000009-00000009.jsonl.gz"), Start: 9, End: 9}
	if err := ReadChunk(missing, func(Entry) error { return nil }); err == nil {
		t.Fatal("reading a chunk that is not there must fail")
	}
}

func TestParseChunkPathAcceptsOnlyTheCanonicalName(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteChunk(2048, []ct.LeafEntry{{LeafInput: []byte{0}}}); err != nil {
		t.Fatal(err)
	}
	chunks, err := s.Chunks()
	if err != nil || len(chunks) != 1 {
		t.Fatalf("chunks=%v err=%v", chunks, err)
	}
	got, err := ParseChunkPath(chunks[0].Path)
	if err != nil || got != chunks[0] {
		t.Fatalf("ParseChunkPath(%s) = %+v, %v; want %+v", chunks[0].Path, got, err, chunks[0])
	}
	for _, name := range []string{
		"00002048-00002048.jsonl.gz.tmp", // a chunk half written by an interrupted run
		"2048-2048.jsonl.gz",             // not zero padded
		"00000005-00000001.jsonl.gz",     // ends before it starts
		"00002048.jsonl.gz",
		"entries.jsonl.gz",
	} {
		if _, err := ParseChunkPath(filepath.Join(s.Dir, "entries", name)); err == nil {
			t.Errorf("%s was accepted as a chunk name", name)
		}
	}
}

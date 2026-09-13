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
	st, err := s.LoadState()
	if err != nil || st.TreeSize != 0 {
		t.Fatalf("empty state: %+v %v", st, err)
	}
	if err := s.SaveState(State{TreeSize: 7, RootHash: "abc"}); err != nil {
		t.Fatal(err)
	}
	st, _ = s.LoadState()
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

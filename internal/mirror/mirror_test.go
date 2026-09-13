package mirror

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/config"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/ctclient"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

// fakeLog is an in-memory RFC 6962 log that can be told to misbehave.
type fakeLog struct {
	key    *ecdsa.PrivateKey
	leaves [][]byte
	// lieRoot makes get-sth report a wrong root hash.
	lieRoot bool
	// badProof makes get-sth-consistency return garbage.
	badProof bool
}

func (f *fakeLog) hashes() [][]byte {
	out := make([][]byte, len(f.leaves))
	for i, l := range f.leaves {
		out[i] = hasher.HashLeaf(l)
	}
	return out
}

func (f *fakeLog) root(n uint64) []byte {
	rf := compact.RangeFactory{Hash: hasher.HashChildren}
	r := rf.NewEmptyRange(0)
	for _, h := range f.hashes()[:n] {
		_ = r.Append(h, nil)
	}
	if n == 0 {
		return hasher.EmptyRoot()
	}
	root, _ := r.GetRootHash(nil)
	return root
}

func (f *fakeLog) sth(t *testing.T) ct.GetSTHResponse {
	n := uint64(len(f.leaves))
	root := f.root(n)
	if f.lieRoot {
		root = sha256.New().Sum(nil)
	}
	sth := ct.SignedTreeHead{Version: ct.V1, TreeSize: n, Timestamp: uint64(time.Now().UnixMilli())}
	copy(sth.SHA256RootHash[:], root)
	th, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := tls.CreateSignature(*f.key, tls.SHA256, th)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tls.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	return ct.GetSTHResponse{TreeSize: n, Timestamp: sth.Timestamp, SHA256RootHash: root, TreeHeadSignature: raw}
}

func (f *fakeLog) serve(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(f.sth(t))
	})
	mux.HandleFunc("/ct/v1/get-entries", func(w http.ResponseWriter, r *http.Request) {
		var start, end uint64
		if _, err := parseRange(r, &start, &end); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var resp ct.GetEntriesResponse
		for i := start; i <= end && i < uint64(len(f.leaves)); i++ {
			resp.Entries = append(resp.Entries, ct.LeafEntry{LeafInput: f.leaves[i], ExtraData: []byte("extra")})
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/ct/v1/get-sth-consistency", func(w http.ResponseWriter, r *http.Request) {
		var first, second uint64
		if _, err := parseRange2(r, &first, &second); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		nodes, err := proof.Consistency(first, second)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		hs := f.hashes()
		tree := buildTree(hs)
		var pf [][]byte
		for _, id := range nodes.IDs {
			pf = append(pf, tree[id.Level][id.Index])
		}
		pf, err = nodes.Rehash(pf, hasher.HashChildren)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if f.badProof && len(pf) > 0 {
			pf[0] = sha256.New().Sum(nil)
		}
		json.NewEncoder(w).Encode(ct.GetSTHConsistencyResponse{Consistency: pf})
	})
	return httptest.NewServer(mux)
}

// buildTree returns every node hash by level and index for a perfect-enough tree.
func buildTree(leaves [][]byte) map[uint][]([]byte) {
	tree := map[uint][][]byte{0: leaves}
	for lvl := uint(0); len(tree[lvl]) > 1; lvl++ {
		cur := tree[lvl]
		var next [][]byte
		for i := 0; i+1 < len(cur); i += 2 {
			next = append(next, hasher.HashChildren(cur[i], cur[i+1]))
		}
		if len(cur)%2 == 1 {
			next = append(next, cur[len(cur)-1]) // promoted, rehashed by nodes.Rehash
		}
		tree[lvl+1] = next
	}
	return tree
}

func parseRange(r *http.Request, a, b *uint64) (int, error) {
	q := r.URL.Query()
	n1, err := parseU(q.Get("start"), a)
	if err != nil {
		return 0, err
	}
	n2, err := parseU(q.Get("end"), b)
	return n1 + n2, err
}
func parseRange2(r *http.Request, a, b *uint64) (int, error) {
	q := r.URL.Query()
	n1, err := parseU(q.Get("first"), a)
	if err != nil {
		return 0, err
	}
	n2, err := parseU(q.Get("second"), b)
	return n1 + n2, err
}
func parseU(s string, out *uint64) (int, error) {
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		v = v*10 + uint64(c-'0')
	}
	*out = v
	return 1, nil
}

func setup(t *testing.T, n int) (*fakeLog, *httptest.Server, config.Log, *ctclient.Client, *store.Store) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeLog{key: key}
	for i := 0; i < n; i++ {
		f.leaves = append(f.leaves, []byte(strings.Repeat("l", i+1)))
	}
	srv := f.serve(t)
	t.Cleanup(srv.Close)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	id := sha256.Sum256(der)
	l := config.Log{Operator: "test", Shard: "1", URL: srv.URL + "/", TLS: config.TLSSystem,
		Key: base64.StdEncoding.EncodeToString(der), LogID: base64.StdEncoding.EncodeToString(id[:])}
	roots := t.TempDir()
	os.WriteFile(filepath.Join(roots, "dummy_root.pem"), []byte(dummyRootPEM), 0o644)
	cl, err := ctclient.New(roots)
	if err != nil {
		t.Fatal(err)
	}
	cl.Retries = 0
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return f, srv, l, cl, st
}

func TestSyncGrowsAndVerifies(t *testing.T) {
	f, _, l, cl, st := setup(t, 5)
	opt := Options{Batch: 2, ChunkSize: 3}
	res, err := Sync(t.Context(), cl, l, st, opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewSize != 5 || res.ChunksWritten != 2 || !res.NewSTH {
		t.Fatalf("first sync: %+v", res)
	}
	if err := Verify(l, st); err != nil {
		t.Fatal(err)
	}
	// Grow the log; the second sync must fetch only the tail and check consistency.
	for i := 0; i < 4; i++ {
		f.leaves = append(f.leaves, []byte("new"+strings.Repeat("x", i)))
	}
	res, err = Sync(t.Context(), cl, l, st, opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.OldSize != 5 || res.NewSize != 9 || res.ChunksWritten != 2 {
		t.Fatalf("second sync: %+v", res)
	}
	if err := Verify(l, st); err != nil {
		t.Fatal(err)
	}
	// Nothing new: no files change.
	res, err = Sync(t.Context(), cl, l, st, opt)
	if err != nil || res.ChunksWritten != 0 || res.NewSTH {
		t.Fatalf("idle sync: %+v %v", res, err)
	}
}

func TestSyncDetectsWrongRoot(t *testing.T) {
	f, _, l, cl, st := setup(t, 4)
	f.lieRoot = true
	_, err := Sync(t.Context(), cl, l, st, Options{})
	var a *Alert
	if !errorsAs(err, &a) || a.Kind != "root-mismatch" {
		t.Fatalf("want root-mismatch alert, got %v", err)
	}
	if _, err := os.Stat(a.Path); err != nil {
		t.Fatal("alert file missing:", err)
	}
	chunks, _ := st.Chunks()
	if len(chunks) != 0 {
		t.Fatalf("bad chunks must be quarantined, found %d", len(chunks))
	}
	q, _ := filepath.Glob(filepath.Join(st.Dir, "alerts", "*.jsonl.gz"))
	if len(q) != 1 {
		t.Fatalf("want 1 quarantined chunk, got %d", len(q))
	}
	state, _, _ := st.LoadState()
	if state.TreeSize != 0 {
		t.Fatal("state must not advance on a failed verification")
	}
}

func TestSyncDetectsRewrittenHistory(t *testing.T) {
	f, _, l, cl, st := setup(t, 4)
	if _, err := Sync(t.Context(), cl, l, st, Options{}); err != nil {
		t.Fatal(err)
	}
	// The log silently replaces leaf 1 and appends more. Our copy of leaf 1
	// plus the new tail no longer hashes to what the log signs.
	f.leaves[1] = []byte("tampered")
	f.leaves = append(f.leaves, []byte("more"))
	_, err := Sync(t.Context(), cl, l, st, Options{})
	var a *Alert
	if !errorsAs(err, &a) || a.Kind != "root-mismatch" {
		t.Fatalf("want root-mismatch alert, got %v", err)
	}
	state, _, _ := st.LoadState()
	if state.TreeSize != 4 {
		t.Fatal("state must keep the last verified tree")
	}
	chunks, _ := st.Chunks()
	if len(chunks) != 1 || chunks[0].End != 3 {
		t.Fatalf("verified chunks must survive, tail must be quarantined: %+v", chunks)
	}
}

func TestSyncDetectsBadConsistencyProof(t *testing.T) {
	f, _, l, cl, st := setup(t, 4)
	if _, err := Sync(t.Context(), cl, l, st, Options{}); err != nil {
		t.Fatal(err)
	}
	f.leaves = append(f.leaves, []byte("more"))
	f.badProof = true
	_, err := Sync(t.Context(), cl, l, st, Options{})
	var a *Alert
	if !errorsAs(err, &a) || a.Kind != "inconsistent" {
		t.Fatalf("want inconsistent alert, got %v", err)
	}
	state, _, _ := st.LoadState()
	if state.TreeSize != 4 {
		t.Fatal("state must keep the last verified tree")
	}
}

func TestSyncDetectsShrinkAndBadSignature(t *testing.T) {
	f, _, l, cl, st := setup(t, 3)
	if _, err := Sync(t.Context(), cl, l, st, Options{}); err != nil {
		t.Fatal(err)
	}
	f.leaves = f.leaves[:2]
	_, err := Sync(t.Context(), cl, l, st, Options{})
	var a *Alert
	if !errorsAs(err, &a) || a.Kind != "tree-shrunk" {
		t.Fatalf("want tree-shrunk, got %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	l.Key = base64.StdEncoding.EncodeToString(der)
	_, err = Sync(t.Context(), cl, l, st, Options{})
	if !errorsAs(err, &a) || a.Kind != "bad-sth-signature" {
		t.Fatalf("want bad-sth-signature, got %v", err)
	}
}

func TestVerifyDetectsCorruptedChunk(t *testing.T) {
	_, _, l, cl, st := setup(t, 6)
	if _, err := Sync(t.Context(), cl, l, st, Options{ChunkSize: 4}); err != nil {
		t.Fatal(err)
	}
	chunks, _ := st.Chunks()
	// Replace the second chunk with one whose entries differ.
	os.Remove(chunks[1].Path)
	if _, err := st.WriteChunk(chunks[1].Start, []ct.LeafEntry{{LeafInput: []byte("evil")}, {LeafInput: []byte("evil2")}}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(l, st); err == nil || !strings.Contains(err.Error(), "hash to") {
		t.Fatalf("want root mismatch from Verify, got %v", err)
	}
}

func errorsAs(err error, target **Alert) bool {
	for err != nil {
		if a, ok := err.(*Alert); ok {
			*target = a
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// dummyRootPEM is any valid certificate; ctclient.New only needs a PEM to parse.
const dummyRootPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
`

// Review findings: each of the following tests pins one of them.

func TestSyncRecoversFromInterruptedRun(t *testing.T) {
	f, _, l, cl, st := setup(t, 4)
	if _, err := Sync(t.Context(), cl, l, st, Options{}); err != nil {
		t.Fatal(err)
	}
	// Simulate a run killed after WriteChunk but before SaveState.
	f.leaves = append(f.leaves, []byte("a"), []byte("b"))
	if _, err := st.WriteChunk(4, []ct.LeafEntry{{LeafInput: []byte("stale")}, {LeafInput: []byte("stale2")}}); err != nil {
		t.Fatal(err)
	}
	res, err := Sync(t.Context(), cl, l, st, Options{})
	if err != nil {
		t.Fatalf("sync must recover from an orphan chunk: %v", err)
	}
	if res.NewSize != 6 || res.ChunksWritten != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
	if err := Verify(l, st); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsNeverSyncedShard(t *testing.T) {
	_, _, l, _, st := setup(t, 0)
	if err := Verify(l, st); err == nil || !strings.Contains(err.Error(), "never synced") {
		t.Fatalf("verify must fail without state.json, got %v", err)
	}
}

func TestSyncAcceptsEmptyLogThenVerifies(t *testing.T) {
	f, _, l, cl, st := setup(t, 0)
	res, err := Sync(t.Context(), cl, l, st, Options{})
	if err != nil {
		t.Fatalf("empty log must sync cleanly: %v", err)
	}
	if res.NewSize != 0 || !res.NewSTH {
		t.Fatalf("unexpected result %+v", res)
	}
	if err := Verify(l, st); err != nil {
		t.Fatal(err)
	}
	// Second run with the log still empty: no equivocation alert.
	if _, err := Sync(t.Context(), cl, l, st, Options{}); err != nil {
		t.Fatalf("second empty sync: %v", err)
	}
	f.leaves = append(f.leaves, []byte("first"))
	res, err = Sync(t.Context(), cl, l, st, Options{})
	if err != nil || res.NewSize != 1 {
		t.Fatalf("growth from empty: %+v %v", res, err)
	}
}

func TestSyncChecksDiskEvenWhenLogUnchanged(t *testing.T) {
	_, _, l, cl, st := setup(t, 5)
	if _, err := Sync(t.Context(), cl, l, st, Options{ChunkSize: 2}); err != nil {
		t.Fatal(err)
	}
	chunks, _ := st.Chunks()
	os.Remove(chunks[1].Path)
	_, err := Sync(t.Context(), cl, l, st, Options{ChunkSize: 2})
	if err == nil || !strings.Contains(err.Error(), "gap in entries") {
		t.Fatalf("missing chunk must be reported on an idle sync, got %v", err)
	}
	// Corrupt content with the right shape must trip the root check.
	if _, err := st.WriteChunk(chunks[1].Start, []ct.LeafEntry{{LeafInput: []byte("x")}, {LeafInput: []byte("y")}}); err != nil {
		t.Fatal(err)
	}
	_, err = Sync(t.Context(), cl, l, st, Options{ChunkSize: 2})
	var a *Alert
	if !errorsAs(err, &a) || a.Kind != "root-mismatch" || !strings.Contains(a.Msg, "on disk") {
		t.Fatalf("corrupt chunk must raise root-mismatch on an idle sync, got %v", err)
	}
}

func TestIdleSyncTouchesNoFiles(t *testing.T) {
	_, _, l, cl, st := setup(t, 3)
	if _, err := Sync(t.Context(), cl, l, st, Options{}); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, st.Dir)
	if _, err := Sync(t.Context(), cl, l, st, Options{}); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(t, st.Dir); after != before {
		t.Fatalf("idle sync changed files:\n%s\n---\n%s", before, after)
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			sum := sha256.Sum256(b)
			sb.WriteString(p + " " + base64.StdEncoding.EncodeToString(sum[:]) + "\n")
		}
		return nil
	})
	return sb.String()
}

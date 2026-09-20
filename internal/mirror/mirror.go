// Package mirror synchronises one CT log shard into a store and verifies it.
package mirror

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/config"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/ctclient"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

// Options tunes a sync run.
type Options struct {
	Batch     uint64 // entries per get-entries request
	ChunkSize uint64 // max entries per chunk file
	Log       io.Writer
	Now       func() time.Time
}

func (o *Options) defaults() {
	if o.Batch == 0 {
		o.Batch = 256
	}
	if o.ChunkSize == 0 {
		o.ChunkSize = 2048
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Alert is a verification failure. Sync returns it as an error after the
// evidence has been written to disk.
type Alert struct {
	Log  string
	Kind string
	Path string
	Msg  string
}

func (a *Alert) Error() string {
	return fmt.Sprintf("ALERT %s %s: %s (evidence: %s)", a.Log, a.Kind, a.Msg, a.Path)
}

// Result summarises a successful sync of one shard.
type Result struct {
	OldSize, NewSize uint64
	NewSTH           bool
	ChunksWritten    int
}

var hasher = rfc6962.DefaultHasher

const (
	// clockSkew is how far ahead of us a log's clock may be before an STH
	// counts as timestamped in the future. An SCT promises inclusion within
	// the MMD of its own timestamp, so a log running fast quietly buys
	// itself extra time; this bounds how much of that goes unremarked, while
	// leaving room for the ordinary disagreement between two unsynchronised
	// clocks.
	clockSkew = 10 * time.Minute

	// staleGrace is added to the MMD before an old STH becomes an alert.
	// RFC 6962 §3.5 is breached the moment an STH outlives the MMD, but
	// nothing here can ask for a fresh one, and a log that re-signs on a
	// daily cron rather than on demand sits just under its 24-hour MMD by
	// design: VK's closed shards re-sign at 03:42 and nowhere else, so a
	// strict test would alert on the ordinary case. Yandex's own policy
	// ("не допускать сбоев, превышающих MMD более чем на 24 часа") draws the
	// line where the log becomes removable, and so does this. An age past
	// the MMD but inside the grace is logged instead.
	staleGrace = 24 * time.Hour
)

// Sync brings the store up to the log's current STH and verifies the result.
func Sync(ctx context.Context, cl *ctclient.Client, l config.Log, st *store.Store, opt Options) (Result, error) {
	opt.defaults()
	var res Result
	now := opt.Now()
	logf := func(format string, a ...any) { fmt.Fprintf(opt.Log, l.Name()+": "+format+"\n", a...) }

	state, found, err := st.LoadState()
	if err != nil {
		return res, err
	}
	res.OldSize = state.TreeSize

	// A run interrupted between WriteChunk and SaveState leaves unverified
	// chunks behind; drop them so the range is fetched and verified afresh.
	if pruned, err := st.PruneBeyond(state.TreeSize); err != nil {
		return res, err
	} else if len(pruned) > 0 {
		logf("removed %d unverified chunk(s) left by an interrupted run", len(pruned))
	}

	raw, sth, err := cl.GetSTH(ctx, l)
	if err != nil {
		return res, err
	}
	if err := VerifySTHSignature(l, sth); err != nil {
		return res, alert(st, l, "bad-sth-signature", now, map[string]any{"sth": raw, "error": err.Error()}, err.Error())
	}
	signed := time.UnixMilli(int64(sth.Timestamp)).UTC()
	logf("STH size=%d ts=%s age=%s", sth.TreeSize, signed.Format(time.RFC3339), now.UTC().Sub(signed).Round(time.Second))

	// Any STH the log signs is evidence; record it before anything can fail.
	wrote, err := st.AppendSTH(*raw, now)
	if err != nil {
		return res, err
	}
	res.NewSTH = wrote

	if found && sth.TreeSize < state.TreeSize {
		return res, alert(st, l, "tree-shrunk", now, map[string]any{"sth": raw, "state": state},
			fmt.Sprintf("log reports tree_size %d, we already verified %d", sth.TreeSize, state.TreeSize))
	}
	if found && sth.TreeSize == state.TreeSize && store.B64(sth.SHA256RootHash[:]) != state.RootHash {
		return res, alert(st, l, "same-size-different-root", now, map[string]any{"sth": raw, "state": state},
			fmt.Sprintf("tree_size %d has root %s, we verified %s", sth.TreeSize, store.B64(sth.SHA256RootHash[:]), state.RootHash))
	}

	// RFC 6962 §3.5: a log MUST produce on demand an STH no older than its
	// MMD, signing the same root with a fresh timestamp when nothing was
	// submitted. Staleness is the one form of tampering the other checks
	// here cannot see: an STH replayed at us stays validly signed, stays
	// consistent with what we hold and simply hides everything logged since.
	// It is also what a log that has quietly gone dark looks like. Tested
	// after the checks that can contradict what we already verified, since
	// those say more, and after the STH is stored, so the evidence outlives
	// the alert.
	//
	// Every comparison here is written so that a saturated age still lands in
	// the branch it belongs to. Sub pins a difference it cannot represent at
	// MinInt64 or MaxInt64, and negating MinInt64 overflows back to itself,
	// so a log dated centuries ahead would slip past a test written as
	// -age > clockSkew. A timestamp past MaxInt64 milliseconds wraps negative
	// on the way in and reads as the distant past, which the stale branch
	// catches.
	mmd, age := l.MMD(), now.UTC().Sub(signed)
	switch {
	case age > mmd+staleGrace:
		return res, alert(st, l, "stale-sth", now, map[string]any{
			"sth": raw, "age_seconds": int64(age.Seconds()),
			"mmd_seconds": int64(mmd.Seconds()), "grace_seconds": int64(staleGrace.Seconds()),
		}, fmt.Sprintf("STH is %s old; the log's MMD is %s and nothing fresher was served",
			age.Round(time.Second), mmd))
	case age < -clockSkew:
		return res, alert(st, l, "sth-from-future", now, map[string]any{
			"sth": raw, "age_seconds": int64(age.Seconds()), "skew_seconds": int64(clockSkew.Seconds()),
			// Negating age would overflow for a saturated one, so the two
			// timestamps are reported rather than the distance between them.
		}, fmt.Sprintf("STH is timestamped %s, ahead of this run at %s by more than %s",
			signed.Format(time.RFC3339), now.UTC().Format(time.RFC3339), clockSkew))
	case age > mmd:
		logf("WARNING: STH is %s old, past the log's MMD of %s (alert at %s)",
			age.Round(time.Second), mmd, mmd+staleGrace)
	}

	// Fetch [state.TreeSize, sth.TreeSize) into chunk files.
	var written []store.Chunk
	next := state.TreeSize
	for next < sth.TreeSize {
		var buf []ct.LeafEntry
		chunkStart := next
		for next < sth.TreeSize && uint64(len(buf)) < opt.ChunkSize {
			end := min(next+opt.Batch, sth.TreeSize, chunkStart+opt.ChunkSize) - 1
			ents, err := cl.GetEntries(ctx, l, next, end)
			if err != nil {
				return res, rollback(st, written, err)
			}
			buf = append(buf, ents...)
			next += uint64(len(ents))
		}
		c, err := st.WriteChunk(chunkStart, buf)
		if err != nil {
			return res, rollback(st, written, err)
		}
		written = append(written, c)
		logf("wrote %d entries [%d, %d]", len(buf), c.Start, c.End)
	}
	res.ChunksWritten = len(written)

	// Recompute the Merkle root over everything on disk and compare with the
	// STH. This runs even when nothing was fetched, so a chunk that went
	// missing or corrupt since the last run is caught by every sync.
	root, n, err := LocalRoot(st)
	if err != nil {
		return res, rollback(st, written, err)
	}
	if n != sth.TreeSize {
		return res, rollback(st, written, fmt.Errorf("stored %d entries, expected %d", n, sth.TreeSize))
	}
	if !bytes.Equal(root, sth.SHA256RootHash[:]) {
		paths := quarantine(st, written, now)
		what := "entries served"
		if len(written) == 0 {
			what = "entries on disk"
		}
		return res, alert(st, l, "root-mismatch", now, map[string]any{
			"sth": raw, "computed_root": store.B64(root), "quarantined_chunks": paths, "state": state,
		}, fmt.Sprintf("%s for tree_size %d hash to %s, STH says %s", what, sth.TreeSize, store.B64(root), store.B64(sth.SHA256RootHash[:])))
	}

	// Ask the log to prove the new tree extends the one we verified before.
	if found && state.TreeSize > 0 && state.TreeSize < sth.TreeSize {
		pf, err := cl.GetConsistency(ctx, l, state.TreeSize, sth.TreeSize)
		if err != nil {
			return res, rollback(st, written, err)
		}
		oldRoot, err := decodeB64(state.RootHash)
		if err != nil {
			return res, rollback(st, written, err)
		}
		if err := proof.VerifyConsistency(hasher, state.TreeSize, sth.TreeSize, pf, oldRoot, sth.SHA256RootHash[:]); err != nil {
			paths := quarantine(st, written, now)
			return res, alert(st, l, "inconsistent", now, map[string]any{
				"sth": raw, "state": state, "proof": pf, "quarantined_chunks": paths, "error": err.Error(),
			}, fmt.Sprintf("consistency proof %d -> %d failed: %v", state.TreeSize, sth.TreeSize, err))
		}
	}

	// Rewrite state.json only when the verified tree actually moved, so an
	// idle run leaves the working tree untouched and nothing gets committed.
	if !found || state.TreeSize != sth.TreeSize || state.RootHash != store.B64(sth.SHA256RootHash[:]) {
		state = store.State{
			TreeSize:     sth.TreeSize,
			RootHash:     store.B64(sth.SHA256RootHash[:]),
			STHTimestamp: sth.Timestamp,
			Updated:      now.UTC().Format(time.RFC3339),
		}
		if err := st.SaveState(state); err != nil {
			return res, err
		}
	}
	res.NewSize = sth.TreeSize
	return res, nil
}

// Verify recomputes the root from the stored entries and checks it against
// state.json and the last recorded STH. It needs no network. A shard that
// never completed a sync fails: absence of evidence is not evidence.
func Verify(l config.Log, st *store.Store) error {
	state, found, err := st.LoadState()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s: no state.json, the shard was never synced", l.Name())
	}
	root, n, err := LocalRoot(st)
	if err != nil {
		return fmt.Errorf("%s: %w", l.Name(), err)
	}
	if n != state.TreeSize {
		return fmt.Errorf("%s: %d entries on disk, state.json says %d", l.Name(), n, state.TreeSize)
	}
	if got := store.B64(root); got != state.RootHash {
		return fmt.Errorf("%s: entries hash to %s, state.json says %s", l.Name(), got, state.RootHash)
	}
	last, err := st.LastSTH()
	if err != nil {
		return err
	}
	if last == nil {
		return fmt.Errorf("%s: no STH recorded", l.Name())
	}
	sth, err := last.STH.ToSignedTreeHead()
	if err != nil {
		return err
	}
	if sth.TreeSize != state.TreeSize || !bytes.Equal(sth.SHA256RootHash[:], root) {
		return fmt.Errorf("%s: last STH (size %d root %s) does not match verified state (size %d root %s)",
			l.Name(), sth.TreeSize, store.B64(sth.SHA256RootHash[:]), state.TreeSize, state.RootHash)
	}
	if err := VerifySTHSignature(l, sth); err != nil {
		return fmt.Errorf("%s: %w", l.Name(), err)
	}
	return nil
}

// LocalRoot hashes every stored entry into a Merkle root.
func LocalRoot(st *store.Store) ([]byte, uint64, error) {
	rf := compact.RangeFactory{Hash: hasher.HashChildren}
	r := rf.NewEmptyRange(0)
	n, err := st.ForEachEntry(func(e store.Entry) error {
		return r.Append(hasher.HashLeaf(e.LeafInput), nil)
	})
	if err != nil {
		return nil, n, err
	}
	if n == 0 {
		return hasher.EmptyRoot(), 0, nil
	}
	root, err := r.GetRootHash(nil)
	return root, n, err
}

// VerifySTHSignature checks the STH against the log's key from logs.json.
// A log without a known key passes.
func VerifySTHSignature(l config.Log, sth *ct.SignedTreeHead) error {
	der, err := l.KeyDER()
	if err != nil {
		return err
	}
	if der == nil {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("%s: parsing log key: %w", l.Name(), err)
	}
	v, err := ct.NewSignatureVerifier(pub)
	if err != nil {
		return err
	}
	if err := v.VerifySTHSignature(*sth); err != nil {
		return fmt.Errorf("STH signature does not verify with the key in logs.json: %w", err)
	}
	return nil
}

func alert(st *store.Store, l config.Log, kind string, now time.Time, payload map[string]any, msg string) error {
	payload["log"] = l.Name()
	payload["url"] = l.URL
	payload["kind"] = kind
	payload["message"] = msg
	payload["observed"] = now.UTC().Format(time.RFC3339)
	p, err := st.WriteAlert(kind, payload, now)
	if err != nil {
		return errors.Join(fmt.Errorf("%s: %s", kind, msg), err)
	}
	return &Alert{Log: l.Name(), Kind: kind, Path: p, Msg: msg}
}

// rollback removes chunks written during a run that failed for a non-evidentiary
// reason (network error, our own bug) so that the next run starts clean.
func rollback(st *store.Store, written []store.Chunk, cause error) error {
	var errs []error
	for _, c := range written {
		if err := removeChunk(c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(append([]error{cause}, errs...)...)
}

func quarantine(st *store.Store, written []store.Chunk, now time.Time) []string {
	var paths []string
	for _, c := range written {
		if p, err := st.Quarantine(c, now); err == nil {
			paths = append(paths, p)
		}
	}
	return paths
}

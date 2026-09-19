package mirror

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

// testCA signs the certificates the tests put into leaves. The issuer name is
// copied from the parent certificate, so it has to be a real CA template.
type testCA struct {
	key *ecdsa.PrivateKey
	crt *stdx509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{key: key, crt: &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Sub CA"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}}
}

// leaf builds the leaf_input of one log entry for a certificate with the given
// subject common name and SANs.
func (ca *testCA) leaf(t *testing.T, cn string, sans []string, notAfter time.Time) []byte {
	t.Helper()
	return ca.entry(t, cn, sans, notAfter, false)
}

// precertLeaf is the same thing logged as a precertificate.
func (ca *testCA) precertLeaf(t *testing.T, cn string, sans []string, notAfter time.Time) []byte {
	t.Helper()
	return ca.entry(t, cn, sans, notAfter, true)
}

func (ca *testCA) entry(t *testing.T, cn string, sans []string, notAfter time.Time, precert bool) []byte {
	t.Helper()
	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    notAfter.Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, ca.crt, &ca.key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	ts := &ct.TimestampedEntry{Timestamp: uint64(notAfter.Add(-24 * time.Hour).UnixMilli())}
	if precert {
		parsed, err := ctx509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		ts.EntryType = ct.PrecertLogEntryType
		ts.PrecertEntry = &ct.PreCert{TBSCertificate: parsed.RawTBSCertificate}
	} else {
		ts.EntryType = ct.X509LogEntryType
		ts.X509Entry = &ct.ASN1Cert{Data: der}
	}
	b, err := tls.Marshal(ct.MerkleTreeLeaf{
		Version:          ct.V1,
		LeafType:         ct.TimestampedEntryLeafType,
		TimestampedEntry: ts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeTestChunk stores leaves as one chunk of log ("operator/shard") under a
// mirror rooted at root, and returns the reference a summary would be given.
func writeTestChunk(t *testing.T, root, log string, start uint64, leaves [][]byte) ChunkRef {
	t.Helper()
	dir := filepath.Join(root, "data", filepath.FromSlash(log))
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]ct.LeafEntry, 0, len(leaves))
	for _, l := range leaves {
		entries = append(entries, ct.LeafEntry{LeafInput: l})
	}
	c, err := st.WriteChunk(start, entries)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ChunkRefFromPath(root, c.Path)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

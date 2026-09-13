package mirror

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

func TestDomainsAggregatesSANsAndCN(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// The issuer name is copied from the parent certificate, so sign with a CA template.
	ca := &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Sub CA"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	mk := func(cn string, sans []string, notAfter time.Time) []byte {
		tmpl := &stdx509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: cn},
			DNSNames:     sans,
			NotBefore:    notAfter.Add(-time.Hour),
			NotAfter:     notAfter,
		}
		der, err := stdx509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf := ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: uint64(notAfter.Add(-24 * time.Hour).UnixMilli()),
				EntryType: ct.X509LogEntryType,
				X509Entry: &ct.ASN1Cert{Data: der},
			},
		}
		b, err := tls.Marshal(leaf)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	st, _ := store.Open(t.TempDir())
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	st.WriteChunk(0, []ct.LeafEntry{
		{LeafInput: mk("www.example.ru", []string{"www.example.ru", "Example.RU"}, old)},
		{LeafInput: mk("www.example.ru", []string{"www.example.ru"}, fresh)},
		{LeafInput: mk("Some Org", nil, fresh)}, // CN without a dot is not a host name
	})
	acc := map[string]*DomainStat{}
	n, err := Domains(st, acc)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(acc) != 2 {
		t.Fatalf("want 2 domains, got %v", acc)
	}
	www := acc["www.example.ru"]
	if www.Certs != 2 || !www.NotAfter.Equal(fresh) || www.Issuers["Test Sub CA"] != 2 {
		t.Fatalf("www stats: %+v", www)
	}
	if ex := acc["example.ru"]; ex == nil || ex.Certs != 1 || !ex.NotAfter.Equal(old) {
		t.Fatalf("example.ru stats: %+v", ex)
	}
}

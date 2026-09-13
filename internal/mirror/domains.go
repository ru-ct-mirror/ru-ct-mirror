package mirror

import (
	"fmt"
	"sort"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

// DomainStat summarises the certificates seen for one DNS name.
type DomainStat struct {
	Domain    string
	Certs     int
	NotAfter  time.Time // latest expiry among the certificates
	Issuers   map[string]int
	Precerts  int
	FirstSeen time.Time // earliest log timestamp
}

// Domains walks every stored entry and aggregates DNS names from the
// certificate (or precertificate TBS) inside each leaf.
func Domains(st *store.Store, acc map[string]*DomainStat) (uint64, error) {
	return st.ForEachEntry(func(e store.Entry) error {
		var leaf ct.MerkleTreeLeaf
		if _, err := tls.Unmarshal(e.LeafInput, &leaf); err != nil {
			return fmt.Errorf("entry %d: %w", e.Index, err)
		}
		var cert *x509.Certificate
		var err error
		precert := false
		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			cert, err = x509.ParseCertificate(leaf.TimestampedEntry.X509Entry.Data)
		case ct.PrecertLogEntryType:
			cert, err = x509.ParseTBSCertificate(leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			precert = true
		default:
			return nil
		}
		if err != nil && cert == nil {
			// Unparseable leaves are still hashed and verified; they only cannot be summarised.
			return nil
		}
		names := map[string]bool{}
		for _, d := range cert.DNSNames {
			names[strings.ToLower(d)] = true
		}
		if cn := strings.ToLower(cert.Subject.CommonName); cn != "" && strings.Contains(cn, ".") && !strings.Contains(cn, " ") {
			names[cn] = true
		}
		ts := time.UnixMilli(int64(leaf.TimestampedEntry.Timestamp)).UTC()
		for n := range names {
			s := acc[n]
			if s == nil {
				s = &DomainStat{Domain: n, Issuers: map[string]int{}, FirstSeen: ts}
				acc[n] = s
			}
			s.Certs++
			if precert {
				s.Precerts++
			}
			if cert.NotAfter.After(s.NotAfter) {
				s.NotAfter = cert.NotAfter
			}
			if ts.Before(s.FirstSeen) {
				s.FirstSeen = ts
			}
			s.Issuers[cert.Issuer.CommonName]++
		}
		return nil
	})
}

// SortedDomains returns the stats ordered by domain name.
func SortedDomains(acc map[string]*DomainStat) []*DomainStat {
	out := make([]*DomainStat, 0, len(acc))
	for _, s := range acc {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

package mirror

import (
	"fmt"
	"sort"
	"time"

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
		info, ok, err := ParseLeaf(e)
		if err != nil {
			return fmt.Errorf("entry %d: %w", e.Index, err)
		}
		if !ok {
			return nil
		}
		for _, n := range info.Names {
			s := acc[n]
			if s == nil {
				s = &DomainStat{Domain: n, Issuers: map[string]int{}, FirstSeen: info.Logged}
				acc[n] = s
			}
			s.Certs++
			if info.Precert {
				s.Precerts++
			}
			if info.NotAfter.After(s.NotAfter) {
				s.NotAfter = info.NotAfter
			}
			if info.Logged.Before(s.FirstSeen) {
				s.FirstSeen = info.Logged
			}
			s.Issuers[info.Issuer]++
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

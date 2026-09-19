package mirror

import (
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

func TestDomainsAggregatesSANsAndCN(t *testing.T) {
	ca := newTestCA(t)
	mk := func(cn string, sans []string, notAfter time.Time) []byte {
		return ca.leaf(t, cn, sans, notAfter)
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

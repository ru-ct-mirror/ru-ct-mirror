package loglist

import (
	"testing"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/config"
)

const sample = `{"version":"1.0","log_list_timestamp":"2026-01-01T00:00:00Z","operators":[{"name":"Yandex","email":["x@y"],"logs":[
{"description":"A","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==","log_id":"Vh7HRN8a9wLmJoOt38SVz3WjGwxs6KDH6gEDMJC3SIU=","mmd":86400,"url":"https://a.example/1/","state":{"usable":{"timestamp":"2024-11-07T18:00:00Z"}},"temporal_interval":{"start_inclusive":"2026-01-01T00:00:00Z","end_exclusive":"2027-01-01T00:00:00Z"}},
{"description":"B","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWPA3LO1jJwycQcruCqve2RM0M19HF7V9IFCBsekQTWg3ZB8m9OGEdVFVnNvf6T6kuLN2mRV6kfwlFiaurInyjw==","log_id":"GukWh2bX94qcsIb4xJw8Xc64yZMAqa9L/7CbB0+BLBc=","mmd":86400,"url":"https://a.example/2/","state":{"usable":{"timestamp":"2025-11-25T13:00:00Z"}},"temporal_interval":{"start_inclusive":"2027-01-01T00:00:00Z","end_exclusive":"2028-01-01T00:00:00Z"}}
],"tiled_logs":[]}]}`

func TestCompare(t *testing.T) {
	cfg := &config.File{Logs: []config.Log{{Operator: "a", Shard: "1", URL: "https://a.example/1/",
		Key:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==",
		LogID: "Vh7HRN8a9wLmJoOt38SVz3WjGwxs6KDH6gEDMJC3SIU="}}}
	d, err := Compare([]byte(sample), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Unknown) != 1 || len(d.Changed) != 0 {
		t.Fatalf("want 1 unknown (B), got %+v", d)
	}
	cfg.Logs[0].Key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWPA3LO1jJwycQcruCqve2RM0M19HF7V9IFCBsekQTWg3ZB8m9OGEdVFVnNvf6T6kuLN2mRV6kfwlFiaurInyjw=="
	d, _ = Compare([]byte(sample), cfg)
	if len(d.Changed) != 1 {
		t.Fatalf("want key change detected, got %+v", d)
	}
}

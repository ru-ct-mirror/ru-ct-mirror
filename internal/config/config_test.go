package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRealLogsJSON(t *testing.T) {
	f, err := Load(filepath.Join("..", "..", "logs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Logs) < 14 {
		t.Fatalf("only %d logs", len(f.Logs))
	}
}

func TestMMDFallsBackToTheDefault(t *testing.T) {
	if got := (Log{}).MMD(); got != DefaultMMD {
		t.Fatalf("unstated mmd gave %s, want %s", got, DefaultMMD)
	}
	if got := (Log{MMDSeconds: 3600}).MMD(); got != time.Hour {
		t.Fatalf("mmd 3600 gave %s", got)
	}
}

func TestLoadRejectsNegativeMMD(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs.json")
	os.WriteFile(p, []byte(`{"logs":[{"operator":"a","shard":"1","url":"https://x/","tls":"system","mmd":-1}]}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("negative mmd accepted")
	}
}

func TestLoadRejectsBadLogID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs.json")
	os.WriteFile(p, []byte(`{"logs":[{"operator":"a","shard":"1","url":"https://x/","tls":"system",
	"key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==","log_id":"nope"}]}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("mismatched log_id accepted")
	}
}

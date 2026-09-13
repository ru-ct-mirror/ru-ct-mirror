package ctclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/config"
)

func TestPinnedModeRejectsForeignCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tree_size":0,"timestamp":0,"sha256_root_hash":"","tree_head_signature":""}`))
	}))
	defer srv.Close()
	roots := t.TempDir()
	// Use the real pinned roots so the test exercises the production pool.
	for _, f := range []string{"russian_trusted_root_ca.pem", "russian_trusted_sub_ca_2024.pem"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "roots", f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(roots, f), b, 0o644)
	}
	cl, err := New(roots)
	if err != nil {
		t.Fatal(err)
	}
	cl.Retries = 0
	l := config.Log{Operator: "x", Shard: "1", URL: srv.URL + "/", TLS: config.TLSRussianTrusted}
	_, _, err = cl.GetSTH(context.Background(), l)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("pinned client must reject httptest's self-signed cert, got %v", err)
	}
	l.TLS = config.TLSSystem
	_, _, err = cl.GetSTH(context.Background(), l)
	if err == nil {
		t.Fatal("system client must also reject an unknown CA")
	}
}

func TestNewRejectsUnnamedPEM(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "something.pem"), []byte("x"), 0o644)
	if _, err := New(dir); err == nil {
		t.Fatal("PEM files must be named root or sub")
	}
}

// Package ctclient is a minimal RFC 6962 read-only client.
package ctclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/config"
)

const userAgent = "ru-ct-mirror (+https://github.com/ru-ct-mirror/ru-ct-mirror)"

// Client talks to CT logs, choosing trust anchors per log.
type Client struct {
	system  *http.Client
	russian *http.Client
	Retries int
	Backoff time.Duration
}

// New builds a client. rootsDir holds PEM files: names containing "root" are
// trust anchors, names containing "sub" are intermediates that the
// digital.gov.ru servers omit from their TLS chain.
func New(rootsDir string) (*Client, error) {
	roots := x509.NewCertPool()
	inters := x509.NewCertPool()
	files, err := filepath.Glob(filepath.Join(rootsDir, "*.pem"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no PEM files in %s", rootsDir)
	}
	for _, f := range files {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(f)
		var ok bool
		switch {
		case strings.Contains(base, "root"):
			ok = roots.AppendCertsFromPEM(pem)
		case strings.Contains(base, "sub"):
			ok = inters.AppendCertsFromPEM(pem)
		default:
			return nil, fmt.Errorf("%s: file name must contain \"root\" or \"sub\"", f)
		}
		if !ok {
			return nil, fmt.Errorf("%s: no certificate found", f)
		}
	}
	mk := func(cfg *tls.Config) *http.Client {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = cfg
		return &http.Client{Timeout: 90 * time.Second, Transport: t}
	}
	// Go's tls.Config has no "extra intermediates" knob, so verification for the
	// pinned mode is done by hand: skip the built-in check, then verify the
	// served chain against our root with our intermediates and the SNI host name.
	pinned := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			for _, c := range cs.PeerCertificates[1:] {
				inters.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inters,
				DNSName:       cs.ServerName,
			})
			return err
		},
	}
	return &Client{
		system:  mk(nil),
		russian: mk(pinned),
		Retries: 5,
		Backoff: 2 * time.Second,
	}, nil
}

func (c *Client) httpFor(l config.Log) *http.Client {
	if l.TLS == config.TLSRussianTrusted {
		return c.russian
	}
	return c.system
}

// Get fetches url+path with retries and decodes JSON into out.
func (c *Client) get(ctx context.Context, l config.Log, path string, out any) error {
	url := l.URL + path
	var last error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.Backoff * time.Duration(attempt)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.httpFor(l).Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("GET %s: HTTP %d: %.200s", url, resp.StatusCode, body)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return last
			}
			continue
		}
		if err := json.Unmarshal(body, out); err != nil {
			last = fmt.Errorf("GET %s: bad JSON: %w", url, err)
			continue
		}
		return nil
	}
	return fmt.Errorf("GET %s failed after %d attempts: %w", url, c.Retries+1, last)
}

// GetSTH returns the raw get-sth response and its parsed form.
func (c *Client) GetSTH(ctx context.Context, l config.Log) (*ct.GetSTHResponse, *ct.SignedTreeHead, error) {
	var raw ct.GetSTHResponse
	if err := c.get(ctx, l, "ct/v1/get-sth", &raw); err != nil {
		return nil, nil, err
	}
	sth, err := raw.ToSignedTreeHead()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: parsing STH: %w", l.Name(), err)
	}
	return &raw, sth, nil
}

// GetEntries fetches entries [start, end] inclusive; the log may return fewer.
func (c *Client) GetEntries(ctx context.Context, l config.Log, start, end uint64) ([]ct.LeafEntry, error) {
	var resp ct.GetEntriesResponse
	if err := c.get(ctx, l, fmt.Sprintf("ct/v1/get-entries?start=%d&end=%d", start, end), &resp); err != nil {
		return nil, err
	}
	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("%s: get-entries %d-%d returned no entries", l.Name(), start, end)
	}
	if uint64(len(resp.Entries)) > end-start+1 {
		return nil, fmt.Errorf("%s: get-entries %d-%d returned %d entries", l.Name(), start, end, len(resp.Entries))
	}
	return resp.Entries, nil
}

// GetConsistency returns the consistency proof between tree sizes first and second.
func (c *Client) GetConsistency(ctx context.Context, l config.Log, first, second uint64) ([][]byte, error) {
	var resp ct.GetSTHConsistencyResponse
	if err := c.get(ctx, l, fmt.Sprintf("ct/v1/get-sth-consistency?first=%d&second=%d", first, second), &resp); err != nil {
		return nil, err
	}
	return resp.Consistency, nil
}

// GetJSON fetches an arbitrary URL with the system trust store (used for ctlog.json).
func (c *Client) GetJSON(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.system.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// Package config loads logs.json, the mirror's own list of CT log shards.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// DefaultMMD is the maximum merge delay assumed for a shard whose logs.json
// entry does not state one. Every log on Yandex's list declares 86400.
const DefaultMMD = 24 * time.Hour

// maxMMDSeconds bounds what logs.json may declare. Every log on Yandex's
// list says 86400 and Chrome's policy caps RFC 6962 logs at four hours, so a
// week is already far outside anything a real log publishes; the bound is
// here so that an MMD read from a file can be turned into a time.Duration and
// added to without overflowing.
const maxMMDSeconds = 7 * 24 * 60 * 60

// TLSMode selects which trust anchors are used for a log's HTTPS endpoint.
type TLSMode string

const (
	// TLSSystem uses the operating system trust store.
	TLSSystem TLSMode = "system"
	// TLSRussianTrusted uses only the pinned Russian Trusted Root CA from roots/.
	TLSRussianTrusted TLSMode = "russian-trusted"
)

// Log describes one CT log shard.
type Log struct {
	Operator    string  `json:"operator"`
	Shard       string  `json:"shard"`
	Description string  `json:"description"`
	URL         string  `json:"url"`
	LogID       string  `json:"log_id"`
	Key         string  `json:"key"`
	TLS         TLSMode `json:"tls"`
	KeySource   string  `json:"key_source"`
	// MMDSeconds is the log's declared maximum merge delay, copied from
	// ctlog.json. Zero means unstated; use MMD rather than reading it.
	MMDSeconds int64  `json:"mmd,omitempty"`
	Disabled   bool   `json:"disabled,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Name is the operator/shard pair used in paths and messages.
func (l Log) Name() string { return l.Operator + "/" + l.Shard }

// MMD is the log's maximum merge delay. RFC 6962 §3.5 requires a log to
// produce on demand an STH no older than this, signing the same root with a
// fresh timestamp when nothing was submitted, so an STH older than the MMD is
// a breach of the log's own published terms and not merely a quiet log.
func (l Log) MMD() time.Duration {
	if l.MMDSeconds <= 0 {
		return DefaultMMD
	}
	return time.Duration(l.MMDSeconds) * time.Second
}

// KeyDER returns the log's SubjectPublicKeyInfo, or nil when unknown.
func (l Log) KeyDER() ([]byte, error) {
	if l.Key == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(l.Key)
}

// File is the top-level structure of logs.json.
type File struct {
	LogListURL string `json:"log_list_url"`
	Logs       []Log  `json:"logs"`
}

// Load reads and validates logs.json.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, l := range f.Logs {
		if l.Operator == "" || l.Shard == "" || l.URL == "" {
			return nil, fmt.Errorf("%s: log %q lacks operator, shard or url", path, l.Description)
		}
		if strings.ContainsAny(l.Operator+l.Shard, "/\\ ") {
			return nil, fmt.Errorf("%s: %s: operator/shard must be path-safe", path, l.Name())
		}
		if !strings.HasSuffix(l.URL, "/") {
			return nil, fmt.Errorf("%s: %s: url must end with /", path, l.Name())
		}
		if seen[l.Name()] {
			return nil, fmt.Errorf("%s: duplicate log %s", path, l.Name())
		}
		seen[l.Name()] = true
		if l.MMDSeconds < 0 || l.MMDSeconds > maxMMDSeconds {
			return nil, fmt.Errorf("%s: %s: mmd must be between 0 and %d seconds, got %d",
				path, l.Name(), maxMMDSeconds, l.MMDSeconds)
		}
		switch l.TLS {
		case TLSSystem, TLSRussianTrusted:
		default:
			return nil, fmt.Errorf("%s: %s: unknown tls mode %q", path, l.Name(), l.TLS)
		}
		der, err := l.KeyDER()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: bad key: %w", path, l.Name(), err)
		}
		if der != nil {
			id := sha256.Sum256(der)
			if got := base64.StdEncoding.EncodeToString(id[:]); got != l.LogID {
				return nil, fmt.Errorf("%s: %s: log_id %s does not match sha256(key) %s", path, l.Name(), l.LogID, got)
			}
		}
	}
	return &f, nil
}

// Package config loads logs.json, the mirror's own list of CT log shards.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

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
	Disabled    bool    `json:"disabled,omitempty"`
	Note        string  `json:"note,omitempty"`
}

// Name is the operator/shard pair used in paths and messages.
func (l Log) Name() string { return l.Operator + "/" + l.Shard }

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

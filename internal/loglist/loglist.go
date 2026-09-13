// Package loglist fetches Yandex Browser's ctlog.json and compares it with logs.json.
package loglist

import (
	"encoding/base64"
	"fmt"

	"github.com/google/certificate-transparency-go/loglist3"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/config"
)

// Diff describes how the published list disagrees with logs.json.
type Diff struct {
	// Unknown lists logs present in ctlog.json but absent from logs.json.
	Unknown []string
	// Changed lists logs whose key or log_id differs between the two files.
	Changed []string
}

// Empty reports whether the lists agree.
func (d Diff) Empty() bool { return len(d.Unknown) == 0 && len(d.Changed) == 0 }

// Compare parses ctlog.json (Chrome log_list v3 schema) and checks it against cfg.
func Compare(ctlogJSON []byte, cfg *config.File) (Diff, error) {
	var d Diff
	ll, err := loglist3.NewFromJSON(ctlogJSON)
	if err != nil {
		return d, fmt.Errorf("parsing ctlog.json: %w", err)
	}
	byURL := map[string]config.Log{}
	for _, l := range cfg.Logs {
		byURL[l.URL] = l
	}
	for _, op := range ll.Operators {
		for _, l := range op.Logs {
			key := base64.StdEncoding.EncodeToString(l.Key)
			id := base64.StdEncoding.EncodeToString(l.LogID)
			known, ok := byURL[l.URL]
			if !ok {
				d.Unknown = append(d.Unknown, fmt.Sprintf("%s %s (%s) key=%s", op.Name, l.Description, l.URL, key))
				continue
			}
			if known.Key != key || known.LogID != id {
				d.Changed = append(d.Changed, fmt.Sprintf("%s: ctlog.json key=%s log_id=%s, logs.json key=%s log_id=%s", known.Name(), key, id, known.Key, known.LogID))
			}
		}
	}
	return d, nil
}

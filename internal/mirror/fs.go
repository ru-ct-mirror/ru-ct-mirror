package mirror

import (
	"encoding/base64"
	"os"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

func removeChunk(c store.Chunk) error { return os.Remove(c.Path) }

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

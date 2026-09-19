package mirror

import (
	"sort"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

// LeafInfo is what a summary needs from one log entry.
type LeafInfo struct {
	Names    []string  // lowercased DNS names, sorted and deduplicated
	Precert  bool      // the entry is a precertificate
	Logged   time.Time // the SCT timestamp, UTC
	NotAfter time.Time // the certificate's expiry
	Issuer   string    // the issuer's common name
}

// ParseLeaf decodes the Merkle tree leaf in e and extracts the names it
// certifies. ok is false when the entry is not a certificate entry or when the
// certificate cannot be parsed at all: such entries are still hashed and
// verified, they only cannot be summarised. A non-nil error means the leaf
// itself does not decode, which is corruption rather than an odd certificate.
func ParseLeaf(e store.Entry) (LeafInfo, bool, error) {
	var leaf ct.MerkleTreeLeaf
	if _, err := tls.Unmarshal(e.LeafInput, &leaf); err != nil {
		return LeafInfo{}, false, err
	}
	var cert *x509.Certificate
	var err error
	info := LeafInfo{}
	switch leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		cert, err = x509.ParseCertificate(leaf.TimestampedEntry.X509Entry.Data)
	case ct.PrecertLogEntryType:
		cert, err = x509.ParseTBSCertificate(leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
		info.Precert = true
	default:
		return LeafInfo{}, false, nil
	}
	if err != nil && cert == nil {
		// The parser reports non-fatal errors alongside a usable certificate;
		// only a nil certificate means there is nothing to summarise.
		return LeafInfo{}, false, nil
	}
	names := map[string]bool{}
	for _, d := range cert.DNSNames {
		names[strings.ToLower(d)] = true
	}
	if cn := strings.ToLower(cert.Subject.CommonName); cn != "" && strings.Contains(cn, ".") && !strings.Contains(cn, " ") {
		names[cn] = true
	}
	info.Names = make([]string, 0, len(names))
	for n := range names {
		info.Names = append(info.Names, n)
	}
	// Sorted, not map order: a summary built from this ends up in a commit
	// message that must be the same on every run.
	sort.Strings(info.Names)
	info.Logged = time.UnixMilli(int64(leaf.TimestampedEntry.Timestamp)).UTC()
	info.NotAfter = cert.NotAfter
	info.Issuer = cert.Issuer.CommonName
	return info, true, nil
}

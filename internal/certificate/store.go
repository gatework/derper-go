package certificate

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Store publishes immutable certificate snapshots after complete file publication.
// A post-publication sync failure retains the usable snapshot and is retried locally.
// TLS handshakes only load an atomic pointer; no disk or network work is done.
type Store struct {
	domain    string
	current   atomic.Pointer[tls.Certificate]
	needsSync atomic.Bool
	cachePath string
	lock      *os.File
}

func (m *Store) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil && hello.ServerName != "" && !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), m.domain) {
		return nil, fmt.Errorf("unconfigured TLS server name")
	}
	cert := m.current.Load()
	if cert == nil {
		return nil, fmt.Errorf("ACME certificate is not ready")
	}
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("ACME certificate is outside its validity period")
	}
	return cert, nil
}

package certificate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/gatework/derper-go/internal/cloudflare"
)

// Manual validates one complete snapshot. Subsequent calls do no filesystem I/O.
func Manual(hostname, certPath, keyPath string) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	cert, err := readFile(certPath, 1<<20)
	if err != nil {
		return nil, err
	}
	key, err := readFile(keyPath, 1<<20)
	if err != nil {
		return nil, err
	}
	m := &Store{domain: hostname}
	pair, err := m.parseCertificate(append(append(cert, '\n'), key...))
	if err != nil {
		return nil, err
	}
	m.current.Store(pair)
	if _, err = m.GetCertificate(nil); err != nil {
		return nil, err
	}
	return m.GetCertificate, nil
}

func Import(c Options, certPath, keyPath string) error {
	m, err := New(c, nil, nil)
	if err != nil {
		return err
	}
	defer m.Close()
	cert, err := readFile(certPath, 1<<20)
	if err != nil {
		return err
	}
	key, err := readFile(keyPath, 1<<20)
	if err != nil {
		return err
	}
	if err = m.openCache(); err != nil {
		return err
	}
	return m.install(append(append(cert, '\n'), key...))
}

func Renew(ctx context.Context, c Options, force bool) error {
	m, err := New(c, nil, nil)
	if err != nil {
		return err
	}
	defer m.Close()
	if err = m.openCache(); err != nil {
		return err
	}
	if err = m.loadCertificate(); err != nil {
		return err
	}
	m.dns = cloudflare.NewSource(m.token, m.config.Cloudflare.ZoneID, m.http)
	if force || m.renewDue(time.Now()) {
		return m.renew(ctx)
	}
	return m.cleanupPending(ctx)
}

type Status struct {
	Domain    string    `json:"domain"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Serial    string    `json:"serial"`
	Valid     bool      `json:"valid"`
}

func CertificateStatus(c *x509.Certificate, domain string) Status {
	now := time.Now()
	return Status{domain, c.NotBefore, c.NotAfter, c.SerialNumber.String(), !now.Before(c.NotBefore) && now.Before(c.NotAfter)}
}
func CachedStatus(c Options) (Status, error) {
	// This read is independent of the writer lock and observes an atomic bundle.
	m, err := New(c, nil, nil)
	if err != nil {
		return Status{}, err
	}
	m.cachePath = cachePath(m.config)
	if err = m.loadCertificate(); err != nil {
		return Status{}, err
	}
	pair := m.current.Load()
	if pair == nil {
		return Status{}, errors.New("no cached certificate")
	}
	return CertificateStatus(pair.Leaf, m.config.Domain), nil
}

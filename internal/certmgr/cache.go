package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gatework/derper-go/internal/fileio"
)

func (m *Manager) openCache() error {
	m.cachePath = cachePath(m.config)
	if err := os.MkdirAll(m.cachePath, 0700); err != nil {
		return err
	}
	if err := os.Chmod(m.cachePath, 0700); err != nil {
		return err
	}
	f, err := openRegularFile(filepath.Join(m.cachePath, "lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return fmt.Errorf("ACME cache is already in use: %w", err)
	}
	m.lock = f
	return nil
}

func cachePath(c Config) string {
	sum := sha256.Sum256([]byte(c.DirectoryURL + "\n" + c.Domain))
	return filepath.Join(c.CacheDir, hex.EncodeToString(sum[:]))
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".acme-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (m *Manager) accountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(m.cachePath, "account.pem")
	b, err := readFile(path, 16<<10)
	if err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("invalid ACME account key PEM")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid ACME account key: %w", err)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err = atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *Manager) parseCertificate(bundle []byte) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return nil, fmt.Errorf("parse ACME certificate: %w", err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err = pair.Leaf.VerifyHostname(m.config.Domain); err != nil {
		return nil, err
	}
	if pair.Leaf.IsCA {
		return nil, fmt.Errorf("ACME leaf certificate must not be a CA")
	}
	if len(pair.Leaf.ExtKeyUsage) > 0 {
		valid := false
		for _, usage := range pair.Leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("ACME certificate does not permit server authentication")
		}
	}
	return &pair, nil
}

func (m *Manager) loadCertificate() error {
	b, err := readFile(filepath.Join(m.cachePath, "certificate.pem"), 1<<20)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	pair, err := m.parseCertificate(b)
	if err != nil {
		return err
	}
	m.current.Store(pair)
	return nil
}

func (m *Manager) install(bundle []byte) error {
	pair, err := m.parseCertificate(bundle)
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
		return fmt.Errorf("ACME returned a certificate outside its validity period")
	}
	if err = atomicWrite(filepath.Join(m.cachePath, "certificate.pem"), bundle); err != nil {
		return fmt.Errorf("save ACME certificate: %w", err)
	}
	// 磁盘完整替换成功后才发布新证书，握手无需磁盘或网络 I/O。
	m.current.Store(pair)
	return nil
}

// ReadCachedCertificate reads an existing valid leaf without credentials, network or cache writes.
func ReadCachedCertificate(c Config) ([]byte, error) {
	m, err := New(c, nil, nil)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(m.config.DirectoryURL + "\n" + m.config.Domain))
	m.cachePath = filepath.Join(m.config.CacheDir, hex.EncodeToString(sum[:]))
	if err = m.loadCertificate(); err != nil {
		return nil, err
	}
	pair, err := m.GetCertificate(nil)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), nil
}

// openRegularFile 拒绝可能阻塞停机的特殊文件。
func openRegularFile(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("ACME file must be regular")
	}
	return f, nil
}
func readFile(path string, limit int64) ([]byte, error) { return fileio.ReadRegularFile(path, limit) }

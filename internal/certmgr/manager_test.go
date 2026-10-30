package certmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testBundle(t *testing.T, domain string, expiry time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(expiry.UnixNano()), DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})...)
}

func TestCertificatePersistenceAndReplacement(t *testing.T) {
	c := testConfig(t)
	m, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.openCache(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	other, _ := New(c, nil, nil)
	if err = other.openCache(); err == nil {
		other.Close()
		t.Fatal("cache lock allowed second owner")
	}
	first := testBundle(t, c.Domain, time.Now().Add(24*time.Hour))
	if err = m.install(first); err != nil {
		t.Fatal(err)
	}
	cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: c.Domain})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.install(testBundle(t, "wrong.example.com", time.Now().Add(time.Hour))); err == nil {
		t.Fatal("wrong domain accepted")
	}
	still, _ := m.GetCertificate(nil)
	if still != cert {
		t.Fatal("failed replacement lost old certificate")
	}
	if _, err = m.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err == nil {
		t.Fatal("unconfigured SNI accepted")
	}
	info, err := os.Stat(filepath.Join(m.cachePath, "certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("certificate mode %o", info.Mode().Perm())
	}
	m.Close()
	restarted, _ := New(c, nil, nil)
	if err = restarted.openCache(); err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err = restarted.loadCertificate(); err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Leaf.SerialNumber.IsInt64() || loaded.Leaf.SerialNumber.Cmp(cert.Leaf.SerialNumber) != 0 {
		t.Fatal("cache was not restored")
	}
}

func TestExpiredCertificateAndCancel(t *testing.T) {
	m, err := New(testConfig(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 直接解析同一份缓存，验证握手时的过期检查。
	b := testBundle(t, m.config.Domain, time.Now().Add(-time.Second))
	pair, err := tls.X509KeyPair(b, b)
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	m.current.Store(&pair)
	if _, err = m.GetCertificate(nil); err == nil {
		t.Fatal("expired certificate served")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestMaintenanceRetriesBeforeRegularInterval(t *testing.T) {
	m, err := New(testConfig(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan time.Time, 8)
	done := make(chan struct{})
	m.wg.Add(1)
	go func() {
		attempts := 0
		m.maintain(ctx, time.Second, "test maintenance", func(context.Context) error {
			attempts++
			calls <- time.Now()
			if attempts < 3 {
				return errors.New("temporary control-plane failure")
			}
			return nil
		}, true)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	first := <-calls
	var recovered time.Time
	for i := 0; i < 2; i++ {
		select {
		case recovered = <-calls:
		case <-time.After(600 * time.Millisecond):
			t.Fatal("transient failure waited for the full maintenance interval")
		}
	}
	if recovered.Sub(first) < 250*time.Millisecond {
		t.Fatal("repeated failures did not back off")
	}
	select {
	case <-calls:
		t.Fatal("successful maintenance kept the short failure retry cadence")
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance did not stop during retry/interval wait")
	}
}

func TestCertificateCheckDelay(t *testing.T) {
	now := time.Date(2026, time.October, 20, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
		want                time.Duration
	}{
		{"long_lifetime", now.Add(-24 * time.Hour), now.Add(89 * 24 * time.Hour), time.Hour},
		{"short_lifetime", now.Add(-time.Minute), now.Add(5 * time.Minute), 3 * time.Minute},
		{"at_renewal", now.Add(-4 * time.Minute), now.Add(2 * time.Minute), 0},
		{"before_renewal", now.Add(-4 * time.Minute), now.Add(2*time.Minute + 3*time.Nanosecond), 2 * time.Nanosecond},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), 0},
		{"not_yet_valid", now.Add(time.Minute), now.Add(time.Hour), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(testConfig(t), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.certificateCheckDelay(now); got != 0 {
				t.Fatalf("missing certificate delay=%s", got)
			}
			m.current.Store(&tls.Certificate{Leaf: &x509.Certificate{NotBefore: tc.notBefore, NotAfter: tc.notAfter}})
			if got := m.certificateCheckDelay(now); got != tc.want {
				t.Fatalf("check delay=%s want=%s", got, tc.want)
			}
		})
	}
}

func TestMaintenanceHandlesNewlyDueState(t *testing.T) {
	m, err := New(testConfig(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 3)
	done := make(chan struct{})
	due := false
	m.wg.Add(1)
	go func() {
		m.maintainScheduled(ctx, time.Hour, "test maintenance", func(context.Context) error {
			// 维护期间跨过续期点；本次只完成清理，尚未执行到期处理。
			due = true
			calls <- struct{}{}
			return nil
		}, true, func(time.Time) time.Duration {
			if due {
				return 0
			}
			return time.Hour
		})
		close(done)
	}()
	defer func() { cancel(); <-done }()
	for attempt := 0; attempt < 2; attempt++ {
		select {
		case <-calls:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("maintenance postponed a newly due state")
		}
	}
	select {
	case <-calls:
		t.Fatal("successful due-state handling entered a busy loop")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCertificateRetryDelay(t *testing.T) {
	now := time.Date(2026, time.October, 20, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name            string
		remaining, want time.Duration
	}{
		{"short_lifetime", 6 * time.Second, 3 * time.Second},
		{"long_lifetime", time.Minute, 30 * time.Second},
		{"minimal_lifetime", time.Nanosecond, time.Nanosecond},
		{"at_expiry", 0, 30 * time.Second},
		{"expired", -time.Second, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(testConfig(t), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.certificateRetryDelay(now, 30*time.Second); got != 30*time.Second {
				t.Fatalf("missing certificate retry delay=%s", got)
			}
			m.current.Store(&tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(tc.remaining)}})
			if got := m.certificateRetryDelay(now, 30*time.Second); got != tc.want {
				t.Fatalf("retry delay=%s want=%s", got, tc.want)
			}
			// 调度必须读取当前已发布证书，不能保留上次短期证书的期限。
			m.current.Store(&tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(time.Hour)}})
			if got := m.certificateRetryDelay(now, 30*time.Second); got != 30*time.Second {
				t.Fatalf("replacement certificate retry delay=%s", got)
			}
		})
	}
}

func TestOfflineReadMatchesActiveCertificate(t *testing.T) {
	c := testConfig(t)
	m, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.openCache(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i := 0; i < 3; i++ {
		if err = m.install(testBundle(t, c.Domain, time.Now().Add(time.Duration(i+1)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	b, err := ReadCachedCertificate(c)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(b)
	current, _ := m.GetCertificate(nil)
	if block == nil || string(block.Bytes) != string(current.Certificate[0]) || len(rest) != 0 {
		t.Fatal("offline leaf did not match active certificate")
	}
}

func TestManagerStartIsSingleUse(t *testing.T) {
	for _, before := range []string{"close", "failure"} {
		t.Run(before, func(t *testing.T) {
			calls := 0
			m, err := New(testConfig(t), nil, func(string) string { calls++; return "" })
			if err != nil {
				t.Fatal(err)
			}
			if before == "close" {
				m.Close()
			} else if err = m.Start(context.Background()); err == nil {
				t.Fatal("missing token accepted")
			}
			beforeCalls := calls
			if err = m.Start(context.Background()); err == nil {
				t.Fatal("second lifecycle accepted")
			}
			if calls != beforeCalls {
				t.Fatal("closed manager performed token I/O")
			}
			m.Close()
		})
	}
}

func TestManagerCloseWaitsForStarting(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	m, err := New(testConfig(t), nil, func(string) string { close(entered); <-release; return "" })
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- m.Start(context.Background()) }()
	<-entered
	if err = m.Start(context.Background()); err == nil {
		t.Fatal("concurrent Start accepted")
	}
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before Start cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked against failed Start")
	}
	if err = <-started; err == nil {
		t.Fatal("start unexpectedly succeeded")
	}
	m.Close()
}

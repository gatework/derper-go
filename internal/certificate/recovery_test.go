package certificate

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestValidCacheStartsWithoutCredentials(t *testing.T) {
	c := renewalOptions(t)
	seed, _ := New(c, nil, nil)
	if err := seed.openCache(); err != nil {
		t.Fatal(err)
	}
	if err := seed.install(testBundle(t, c.Domain, time.Now().Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	seed.Close()
	m, err := New(c, nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.Start(context.Background()); err != nil {
		t.Fatal("valid cache required control-plane credentials:", err)
	}
	if _, err = m.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
}

func TestRetryAfterSurvivesRestart(t *testing.T) {
	c := renewalOptions(t)
	m, _ := New(c, nil, nil)
	if err := m.openCache(); err != nil {
		t.Fatal(err)
	}
	rateErr := &acme.Error{StatusCode: 429, Header: http.Header{"Retry-After": []string{"3600"}}}
	if err := m.rememberRetry(rateErr); err != nil {
		t.Fatal(err)
	}
	m.Close()
	m, _ = New(c, nil, nil)
	if err := m.openCache(); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	err := m.renew(context.Background())
	var window *retryWindow
	if !errors.As(err, &window) || retryDelay(err) < 59*time.Minute {
		t.Fatalf("retry state lost: %v", err)
	}
	if err = m.rememberRetry(nil); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(m.cachePath, "retry.json")); !os.IsNotExist(err) {
		t.Fatal("completed retry state retained")
	}
}

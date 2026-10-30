package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type acmeFixture struct {
	certificateLifetime, certificateBackdate time.Duration
	mu                                       sync.Mutex
	server                                   *httptest.Server
	domain                                   string
	a                                        record
	txt                                      []record
	orders, deleted                          int
	accepted, finalized, fail                bool
	failDelete                               bool
	expectedTXT                              string
	certificate                              []byte
	caKey                                    *ecdsa.PrivateKey
	ca                                       *x509.Certificate
}

func newACMEFixture(t *testing.T, domain string) *acmeFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	f := &acmeFixture{domain: domain, caKey: key, ca: ca}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
	t.Cleanup(f.server.Close)
	return f
}

func (f *acmeFixture) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprint(time.Now().UnixNano()))))
	w.Header().Set("Content-Type", "application/json")
	send := func(v any) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Error(err)
		}
	}
	if strings.HasPrefix(r.URL.Path, "/client/v4/") {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("cloudflare auth missing")
		}
		switch {
		case r.URL.Path == "/client/v4/zones/0123456789abcdef0123456789abcdef":
			send(map[string]any{"success": true, "result": map[string]string{"name": "example.com", "status": "active"}})
		case r.Method == http.MethodDelete:
			if f.failDelete {
				w.WriteHeader(http.StatusServiceUnavailable)
				send(map[string]any{"success": false})
				return
			}
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			for i, v := range f.txt {
				if v.ID == id {
					f.txt = append(f.txt[:i], f.txt[i+1:]...)
					f.deleted++
					break
				}
			}
			send(map[string]any{"success": true, "result": map[string]string{"id": id}})
		case r.Method == http.MethodGet:
			result := []record{}
			if r.URL.Query().Get("name") == f.domain {
				if f.a.ID != "" {
					result = append(result, f.a)
				}
			} else {
				result = append(result, f.txt...)
			}
			send(map[string]any{"success": true, "result": result, "result_info": map[string]int{"total_pages": 1}})
		default:
			var v record
			if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
				t.Error(err)
				return
			}
			if v.Type == "A" {
				v.ID = "address"
				f.a = v
			} else {
				// Cloudflare 存储带引号的 TXT 表示，DNS 查询返回原始值。
				value := fixtureTXTValue(v.Content)
				if v.Content != strconv.Quote(value) {
					t.Error("Cloudflare TXT create content must use quoted character-string presentation")
				}
				v.Content = strconv.Quote(value)
				v.ID = fmt.Sprintf("txt-%d", f.orders)
				f.txt = append(f.txt, v)
			}
			send(map[string]any{"success": true, "result": v})
		}
		return
	}
	if r.URL.Path == "/directory" {
		send(map[string]string{"newNonce": f.server.URL + "/nonce", "newAccount": f.server.URL + "/account", "newOrder": f.server.URL + "/new-order"})
		return
	}
	if r.URL.Path == "/nonce" {
		w.WriteHeader(200)
		return
	}
	var envelope struct{ Payload, Protected string }
	if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
		t.Error(err)
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Error(err)
		return
	}
	order := func(status string) map[string]any {
		return map[string]any{"status": status, "authorizations": []string{f.server.URL + "/auth"}, "finalize": f.server.URL + "/finalize", "certificate": f.server.URL + "/certificate"}
	}
	switch r.URL.Path {
	case "/account":
		protected, _ := base64.RawURLEncoding.DecodeString(envelope.Protected)
		var header struct {
			JWK map[string]any `json:"jwk"`
		}
		if err = json.Unmarshal(protected, &header); err != nil {
			t.Error(err)
		}
		canonical, _ := json.Marshal(header.JWK)
		thumb := sha256.Sum256(canonical)
		hash := sha256.Sum256([]byte("challenge-token." + base64.RawURLEncoding.EncodeToString(thumb[:])))
		f.expectedTXT = base64.RawURLEncoding.EncodeToString(hash[:])
		w.Header().Set("Location", f.server.URL+"/account/1")
		w.WriteHeader(http.StatusCreated)
		send(map[string]string{"status": "valid"})
	case "/new-order":
		f.orders++
		f.accepted = false
		f.finalized = false
		w.Header().Set("Location", f.server.URL+"/order")
		w.WriteHeader(http.StatusCreated)
		send(order("pending"))
	case "/auth":
		status := "pending"
		if f.accepted {
			status = "valid"
		}
		send(map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": f.domain}, "challenges": []any{map[string]string{"type": "dns-01", "url": f.server.URL + "/challenge", "token": "challenge-token", "status": "pending"}}})
	case "/challenge":
		if f.fail {
			w.WriteHeader(http.StatusBadRequest)
			send(map[string]string{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "forced rejection"})
			return
		}
		matched := false
		for _, r := range f.txt {
			if fixtureTXTValue(r.Content) == f.expectedTXT {
				matched = true
			}
		}
		if !matched {
			t.Error("CA could not validate the TXT key authorization")
		}
		f.accepted = true
		send(map[string]string{"type": "dns-01", "status": "valid", "url": f.server.URL + "/challenge", "token": "challenge-token"})
	case "/order":
		status := "pending"
		if f.accepted {
			status = "ready"
		}
		if f.finalized {
			status = "valid"
		}
		w.Header().Set("Location", f.server.URL+"/order")
		send(order(status))
	case "/finalize":
		var body struct {
			CSR string `json:"csr"`
		}
		if err = json.Unmarshal(payload, &body); err != nil {
			t.Error(err)
			return
		}
		der, _ := base64.RawURLEncoding.DecodeString(body.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Error(err)
			return
		}
		if err = csr.CheckSignature(); err != nil {
			t.Error(err)
		}
		if len(csr.DNSNames) != 1 || csr.DNSNames[0] != f.domain {
			t.Errorf("unexpected CSR names: %v", csr.DNSNames)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(f.orders + 1)), DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if f.certificateLifetime > 0 {
			leaf.NotBefore = time.Now().Add(-f.certificateBackdate)
			leaf.NotAfter = time.Now().Add(f.certificateLifetime)
		}
		cert, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, csr.PublicKey, f.caKey)
		if err != nil {
			t.Error(err)
			return
		}
		f.certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		f.finalized = true
		w.Header().Set("Location", f.server.URL+"/order")
		send(order("valid"))
	case "/certificate":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(f.certificate)
	default:
		t.Errorf("unexpected ACME request %s", r.URL)
		w.WriteHeader(404)
	}
}

func fixtureTXTValue(content string) string {
	if value, err := strconv.Unquote(content); err == nil {
		return value
	}
	return content
}

func (f *acmeFixture) manager(t *testing.T, c Options) *Renewer {
	t.Helper()
	c.DirectoryURL = f.server.URL + "/directory"
	m, err := New(c, nil, func(string) string { return "test-secret" })
	if err != nil {
		t.Fatal(err)
	}
	transport := f.server.Client().Transport
	base, _ := url.Parse(f.server.URL)
	m.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "api.cloudflare.com" {
			copy := r.Clone(r.Context())
			u := *r.URL
			u.Scheme = base.Scheme
			u.Host = base.Host
			copy.URL = &u
			r = copy
		}
		return transport.RoundTrip(r)
	})
	m.lookupTXT = func(ctx context.Context, name string) ([]string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var values []string
		for _, r := range f.txt {
			if r.Name == name {
				values = append(values, fixtureTXTValue(r.Content))
			}
		}
		return values, nil
	}
	return m
}

func TestACMEIssueRenewRestart(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	f.txt = []record{{ID: "unrelated", Name: "_acme-challenge." + c.Domain, Content: "other-owner", Type: "TXT"}}
	m := f.manager(t, c)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	first, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.orders != 1 || f.deleted != 1 || len(f.txt) != 1 {
		t.Errorf("bad DNS lifecycle: orders=%d deleted=%d TXT=%v A=%v", f.orders, f.deleted, f.txt, f.a)
	}
	f.mu.Unlock()
	// 真实 TLS 握手读取原子发布的证书，续期后新连接获得新证书。
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	tlsServer.TLS = &tls.Config{GetCertificate: m.GetCertificate}
	tlsServer.StartTLS()
	defer tlsServer.Close()
	serial := func() int64 {
		roots := x509.NewCertPool()
		roots.AddCert(f.ca)
		conn, err := tls.Dial("tcp", tlsServer.Listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: c.Domain})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if got := serial(); got != first.Leaf.SerialNumber.Int64() {
		t.Fatalf("initial TLS serial %d", got)
	}
	if err = m.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := serial(); got == first.Leaf.SerialNumber.Int64() {
		t.Fatal("TLS did not reload renewed certificate")
	}
	m.Close()
	restarted := f.manager(t, c)
	if err = restarted.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	f.mu.Lock()
	orders := f.orders
	f.mu.Unlock()
	if orders != 2 {
		t.Fatalf("restart unnecessarily issued order %d", orders)
	}
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	before, _ := restarted.GetCertificate(nil)
	if err = restarted.renew(context.Background()); err == nil {
		t.Fatal("rejected ACME challenge succeeded")
	}
	after, _ := restarted.GetCertificate(nil)
	if after != before {
		t.Fatal("failed renewal replaced certificate")
	}
	f.mu.Lock()
	if len(f.txt) != 1 || f.txt[0].ID != "unrelated" {
		t.Error("failed renewal leaked TXT or deleted another owner")
	}
	f.mu.Unlock()
	if _, err = os.Stat(filepath.Join(restarted.cachePath, "pending-txt.json")); !os.IsNotExist(err) {
		t.Fatalf("cleanup journal remains: %v", err)
	}
}

func TestACMECancelRetainsRecoverableTXT(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	m := f.manager(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	m.lookupTXT = func(ctx context.Context, name string) ([]string, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := m.Start(ctx); err == nil {
		t.Fatal("canceled issuance succeeded")
	}
	f.mu.Lock()
	remaining, deleted := len(f.txt), f.deleted
	f.mu.Unlock()
	if remaining != 1 || deleted != 0 {
		t.Fatalf("canceled issuance lost journal record: remaining=%d deleted=%d", remaining, deleted)
	}
	// Failed startup releases the lock; recovery performs owned cleanup first.
	other := f.manager(t, c)
	if err := other.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	other.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.txt) != 0 {
		t.Fatal("restart failed to clean owned TXT")
	}

}

func TestRestartCleansPendingTXTWithValidCache(t *testing.T) {
	for _, quoted := range []bool{false, true} {
		t.Run(fmt.Sprintf("quoted_API_%v", quoted), func(t *testing.T) {
			c := renewalOptions(t)
			f := newACMEFixture(t, c.Domain)
			m := f.manager(t, c)
			if err := m.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			pending := record{ID: "interrupted", Name: "_acme-challenge." + c.Domain, Type: "TXT", Content: "owned-value"}
			f.mu.Lock()
			published := pending
			if quoted {
				published.Content = strconv.Quote(published.Content)
			}
			f.txt = append(f.txt, published)
			f.mu.Unlock()
			b, _ := json.Marshal(pending)
			if err := atomicWrite(filepath.Join(m.cachePath, "pending-txt.json"), b); err != nil {
				t.Fatal(err)
			}
			m.Close()
			restarted := f.manager(t, c)
			if err := restarted.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			deadline := time.Now().Add(2 * time.Second)
			for {
				f.mu.Lock()
				remaining := len(f.txt)
				f.mu.Unlock()
				if remaining == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("restart left interrupted TXT despite valid cached certificate")
				}
				time.Sleep(5 * time.Millisecond)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.orders != 1 {
				t.Fatal("cleanup unnecessarily issued a certificate")
			}
		})
	}
}

func TestLiveCleanupRefusesModifiedTXT(t *testing.T) {
	for name, modify := range map[string]func(string) string{
		"bare_changed":   func(string) string { return "external-replacement" },
		"quoted_changed": func(string) string { return strconv.Quote("external-replacement") },
		"quoted_literal": strconv.Quote,
		"malformed":      func(value string) string { return value[:len(value)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			c := renewalOptions(t)
			f := newACMEFixture(t, c.Domain)
			m := f.manager(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			var changed string
			m.lookupTXT = func(context.Context, string) ([]string, error) {
				f.mu.Lock()
				f.txt[0].Content = modify(f.txt[0].Content)
				changed = f.txt[0].Content
				f.mu.Unlock()
				cancel()
				return nil, context.Canceled
			}
			if err := m.Start(ctx); err == nil {
				t.Fatal("canceled start succeeded")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.txt) != 1 || f.txt[0].Content != changed {
				t.Fatal("cleanup deleted externally changed TXT")
			}
		})
	}
}

func TestLostTXTCreateResponseIsRecoverable(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	m := f.manager(t, c)
	transport := m.http.Transport
	lost := false
	m.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(r)
		if err == nil && !lost && r.Method == http.MethodPost && strings.Contains(r.URL.Path, "dns_records") {
			f.mu.Lock()
			hasTXT := len(f.txt) > 0
			f.mu.Unlock()
			if hasTXT {
				lost = true
				response.Body.Close()
				return nil, fmt.Errorf("response lost after commit")
			}
		}
		return response, err
	})
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("lost response unexpectedly succeeded")
	}
	if !lost {
		t.Fatal("fault was not injected")
	}
	f.mu.Lock()
	remaining := len(f.txt)
	f.mu.Unlock()
	_, journalErr := os.Stat(filepath.Join(m.cachePath, "pending-txt.json"))
	if remaining != 0 || !os.IsNotExist(journalErr) {
		t.Fatalf("lost response cleanup did not recover the quoted TXT: remaining=%d journal=%v", remaining, journalErr)
	}
}

func TestCachedStartDoesNotWaitForControlPlane(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	m := f.manager(t, c)
	if err := m.openCache(); err != nil {
		t.Fatal(err)
	}
	if err := m.install(testBundle(t, c.Domain, time.Now().Add(5*time.Minute))); err != nil {
		t.Fatal(err)
	}
	m.Close()
	restarted := f.manager(t, c)
	restarted.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := restarted.Start(ctx); err != nil {
		t.Fatalf("cached startup waited for control plane: %v", err)
	}
	defer restarted.Close()
	if _, err := restarted.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
}

func TestIssuanceBudgetIncludesPropagation(t *testing.T) {
	c := renewalOptions(t)
	c.PropagationTimeout = 20 * time.Minute
	m, _ := New(c, nil, nil)
	if m.issuanceTimeout() < 20*time.Minute+time.Minute {
		t.Fatal("issuance budget truncates configured DNS propagation")
	}
}

func TestBackgroundRenewsDueCachedCertificate(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	seed := f.manager(t, c)
	if err := seed.openCache(); err != nil {
		t.Fatal(err)
	}
	if err := seed.install(testBundle(t, c.Domain, time.Now().Add(5*time.Minute))); err != nil {
		t.Fatal(err)
	}
	previous, _ := seed.GetCertificate(nil)
	seed.Close()
	m := f.manager(t, c)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		current, err := m.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		if current.Leaf.SerialNumber.Cmp(previous.Leaf.SerialNumber) != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background maintenance did not renew due cached certificate")
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders != 1 || f.deleted != 1 || len(f.txt) != 0 {
		t.Fatalf("unexpected background issuance: orders=%d cleanup=%d remaining=%d", f.orders, f.deleted, len(f.txt))
	}
}

func TestShortLivedCertificateRenewsBeforeExpiry(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	f.certificateLifetime = 6 * time.Second
	m := f.manager(t, c)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	first, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Until(first.Leaf.NotAfter))
	defer deadline.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("short-lived certificate expired before scheduled renewal")
		case <-poll.C:
			next, err := m.GetCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			if next != first {
				return
			}
		}
	}
}

func TestDueCertificateRenewalDoesNotBusyLoop(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	f.certificateLifetime = 6 * time.Second
	f.certificateBackdate = time.Minute
	m := f.manager(t, c)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	first, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	// 先确认已到续期点的证书立即重签，再观察成功后没有零等待循环。
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		orders := f.orders
		f.mu.Unlock()
		if orders >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("due certificate was not renewed promptly")
		}
		time.Sleep(5 * time.Millisecond)
	}
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	f.mu.Lock()
	orders := f.orders
	f.mu.Unlock()
	if orders > 2 {
		t.Fatalf("due certificate created %d ACME orders in 150ms", orders)
	}
	// 必须跨过初始证书有效期持续提供证书，不能用固定退避换取短期无忙循环。
	deadline = first.Leaf.NotAfter.Add(2 * time.Second)
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for time.Now().Before(deadline) {
		<-poll.C
		if _, err := m.GetCertificate(nil); err != nil {
			t.Fatalf("healthy CA did not keep short-lived certificate available: %v", err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders < 3 || f.orders > 6 {
		t.Fatalf("unexpected successful renewal cadence: %d orders", f.orders)
	}
}

func TestValidCertificateSurvivesTXTCleanupFailure(t *testing.T) {
	c := renewalOptions(t)
	f := newACMEFixture(t, c.Domain)
	f.failDelete = true
	m := f.manager(t, c)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if m.CleanupError() == nil {
		t.Fatal("cleanup failure not reported")
	}
	if _, err := os.Stat(filepath.Join(m.cachePath, "pending-txt.json")); err != nil {
		t.Fatal("lost cleanup journal", err)
	}
	f.mu.Lock()
	f.failDelete = false
	f.mu.Unlock()
	restored := f.manager(t, c)
	if err := restored.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Explicit maintenance models the next background attempt without sleeping.
	restored.certificateMu.Lock()
	err := restored.cleanupPending(context.Background())
	restored.certificateMu.Unlock()
	restored.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.txt) != 0 || f.orders != 1 {
		t.Fatalf("cleanup retried issuance: records=%d orders=%d", len(f.txt), f.orders)
	}
}

package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `{"domain":"Relay.Example.com.","email":"ops@example.com"}`

func TestStrictConfiguration(t *testing.T) {
	for _, s := range []string{`null`, `[]`, `{} {}`, `{"domain":"a.example","Domain":"b.example"}`, `{"domain":null}`, `{"domain":"a.example","unknown":true}`, `{"domain":"a.example","certificate":{"ca":"staging","ca":"staging"}}`} {
		if _, err := Decode([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	c, err := Decode([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxConnections != 2048 || s.MaxConcurrentChecks != 32 || s.Domain != "relay.example.com" || s.Access != Tailnet || s.Port != 443 || s.CaptivePortal || !s.PublishDNS || !s.AutoIPv4 || s.IPv6.IsValid() {
		t.Fatalf("defaults: %+v", s)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"domain":"relay.example.com","email":"ops@example.com"}` {
		t.Fatalf("defaults leaked into intent: %s", b)
	}
}
func TestPathsAndOverrides(t *testing.T) {
	c, err := Decode([]byte(`{"domain":"relay.example.com","port":8443,"access":"public","certificate":{"file":"cert.pem","key":"key.pem"},"dns":{"publish":false},"stun":{"enabled":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	s, err := c.Resolve(base)
	if err != nil {
		t.Fatal(err)
	}
	if s.CertificateFile != filepath.Join(base, "cert.pem") || s.PublishDNS || s.STUNEnabled || s.Port != 8443 || s.Access != Public {
		t.Fatalf("overrides: %+v", s)
	}
}
func TestInvalidSettings(t *testing.T) {
	for _, change := range []func(*Config){func(c *Config) { c.DNS.IPv4 = "127.0.0.1" }, func(c *Config) { c.DNS.IPv4 = "100.64.0.1" }, func(c *Config) { c.DNS.IPv6 = "::ffff:192.0.2.1" }, func(c *Config) { c.Region = 1 }, func(c *Config) { c.Port = -1 }, func(c *Config) { c.DNS.IPv4 = "off" }, func(c *Config) { c.Certificate.CA = "http://bad.example" }} {
		c, _ := Decode([]byte(valid))
		change(&c)
		if c.Validate() == nil {
			t.Fatal("accepted invalid settings")
		}
	}
}
func TestDefaultsNeverStoreSecrets(t *testing.T) {
	c, _ := Decode([]byte(valid))
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "token") {
		t.Fatal(string(b))
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte(valid))
	f.Add([]byte(`{"domain":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 1<<20 {
			_, _ = Decode(b)
		}
	})
}

func TestResourceLimits(t *testing.T) {
	for _, raw := range []string{
		`{"domain":"relay.example.com","email":"ops@example.com","relay":{"max_connections":-1}}`,
		`{"domain":"relay.example.com","email":"ops@example.com","relay":{"max_connections":60001}}`,
		`{"domain":"relay.example.com","email":"ops@example.com","tailscale":{"max_concurrent_checks":129}}`,
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatal("unbounded setting", raw)
		}
	}
}

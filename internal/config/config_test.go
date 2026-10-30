package config

import (
	"os"
	"path/filepath"
	"testing"
)

const valid = `{"hostname":"Relay.Example.com.","tls":{"mode":"manual","certificate":"cert.pem","private_key":"key.pem"}}`

func TestStrictConfiguration(t *testing.T) {
	for _, s := range []string{`null`, `[]`, `{} {}`, `{"hostname":"a.example","Hostname":"b.example"}`, `{"hostname":null}`, `{"hostname":"a.example","unknown":true}`, `{"hostname":"a.example","tls":{"mode":"manual","mode":"acme"}}`} {
		if _, err := Decode([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	c, err := Decode([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Hostname != "relay.example.com" || c.Verification.Mode != "tailscaled" || c.HTTPPort != -1 || c.DNS.Mode != "off" {
		t.Fatal("unexpected defaults")
	}
}
func TestPathsResolveAgainstConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.TLS.Certificate != filepath.Join(dir, "cert.pem") {
		t.Fatal("relative certificate path depends on working directory")
	}
}
func TestRejectConflictingAndPrivateDNS(t *testing.T) {
	for _, change := range []func(*Config){func(c *Config) { c.DNS.Mode = "manage" }, func(c *Config) { c.DNS.IPv4 = "127.0.0.1" }, func(c *Config) { c.DNS.IPv4 = "100.64.0.1" }, func(c *Config) { c.DNS.IPv6 = "::ffff:192.0.2.1" }, func(c *Config) { c.DNS.IPv4 = "192.0.2.1"; c.DNS.IPv4URL = "https://example.com" }, func(c *Config) { c.HTTPPort = 8443 }, func(c *Config) { c.Listen = ":https" }} {
		c, err := Decode([]byte(valid))
		if err != nil {
			t.Fatal(err)
		}
		change(&c)
		if c.Validate() == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte(valid))
	f.Add([]byte(`{"hostname":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = Decode(b)
	})
}

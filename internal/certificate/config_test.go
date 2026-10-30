package certificate

import (
	"testing"
	"time"
)

func testConfig(t *testing.T) Options {
	t.Helper()
	return Options{Domain: "vpn.example.com", Email: "ops@example.com", AcceptTerms: true, CacheDir: t.TempDir(), Cloudflare: CloudflareOptions{ZoneID: "0123456789abcdef0123456789abcdef"}}
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Options)
	}{
		{"wildcard", func(c *Options) { c.Domain = "*.example.com" }},
		{"path", func(c *Options) { c.Domain = "../example.com" }},
		{"zone", func(c *Options) { c.Cloudflare.ZoneID = "../zone" }},
		{"terms", func(c *Options) { c.AcceptTerms = false }},
		{"directory", func(c *Options) { c.DirectoryURL = "http://acme.example.com/directory" }},
		{"token_conflict", func(c *Options) { c.Cloudflare.TokenEnv = "TOKEN"; c.Cloudflare.TokenFile = "token" }},
		{"duration", func(c *Options) { c.PropagationTimeout = -time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(t)
			tc.change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	c := testConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

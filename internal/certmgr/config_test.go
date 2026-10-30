package certmgr

import (
	"testing"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{Domain: "vpn.example.com", Email: "ops@example.com", AcceptTerms: true, CacheDir: t.TempDir(), Cloudflare: CloudflareConfig{ZoneID: "0123456789abcdef0123456789abcdef"}}
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"wildcard", func(c *Config) { c.Domain = "*.example.com" }},
		{"path", func(c *Config) { c.Domain = "../example.com" }},
		{"zone", func(c *Config) { c.Cloudflare.ZoneID = "../zone" }},
		{"terms", func(c *Config) { c.AcceptTerms = false }},
		{"directory", func(c *Config) { c.DirectoryURL = "http://acme.example.com/directory" }},
		{"token_conflict", func(c *Config) { c.Cloudflare.TokenEnv = "TOKEN"; c.Cloudflare.TokenFile = "token" }},
		{"duration", func(c *Config) { c.PropagationTimeout = "-1s" }},
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

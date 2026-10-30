// Package certmgr 管理服务端域名的 DNS 记录与 ACME 证书生命周期。
package certmgr

import (
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

type CloudflareConfig struct {
	ZoneID    string `json:"zone_id"`
	TokenEnv  string `json:"token_env,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
}

type Config struct {
	Domain             string           `json:"domain"`
	Email              string           `json:"email"`
	AcceptTerms        bool             `json:"accept_terms"`
	DirectoryURL       string           `json:"directory_url,omitempty"`
	CacheDir           string           `json:"cache_dir,omitempty"`
	PropagationTimeout string           `json:"propagation_timeout,omitempty"`
	Cloudflare         CloudflareConfig `json:"cloudflare"`
}

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var zoneID = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func (c Config) normalized() Config {
	c.Domain = strings.ToLower(strings.TrimSuffix(c.Domain, "."))
	if c.DirectoryURL == "" {
		c.DirectoryURL = acme.LetsEncryptURL
	}
	if c.CacheDir == "" {
		c.CacheDir = "acme"
	}
	if c.PropagationTimeout == "" {
		c.PropagationTimeout = "2m"
	}
	if c.Cloudflare.TokenEnv == "" && c.Cloudflare.TokenFile == "" {
		c.Cloudflare.TokenEnv = "CLOUDFLARE_API_TOKEN"
	}
	return c
}

// ResolvePaths 在 CLI 加载配置时固定相对路径，包括默认缓存目录。
func (c *Config) ResolvePaths(base string) {
	if c.CacheDir == "" {
		c.CacheDir = "acme"
	}
	for _, p := range []*string{&c.CacheDir, &c.Cloudflare.TokenFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
}

// Validate 只校验结构，不读取凭据、不发起网络请求或创建缓存。
func (c Config) Validate() error {
	c = c.normalized()
	if len(c.Domain) > 253 || !strings.Contains(c.Domain, ".") {
		return fmt.Errorf("acme.domain must be a fully qualified DNS name")
	}
	if _, err := netip.ParseAddr(c.Domain); err == nil {
		return fmt.Errorf("acme.domain must not be an IP address")
	}
	for label := range strings.SplitSeq(c.Domain, ".") {
		if !domainLabel.MatchString(label) {
			return fmt.Errorf("acme.domain must be an ASCII DNS name without wildcards (use punycode for IDNs)")
		}
	}
	email, err := mail.ParseAddress(c.Email)
	if err != nil || email.Address != c.Email {
		return fmt.Errorf("acme.email must be a plain email address")
	}
	if !c.AcceptTerms {
		return fmt.Errorf("acme.accept_terms must be true to accept the CA terms of service")
	}
	if c.Cloudflare.ZoneID != "" && !zoneID.MatchString(c.Cloudflare.ZoneID) {
		return fmt.Errorf("acme.cloudflare.zone_id must be a 32-character hexadecimal zone ID")
	}
	if c.Cloudflare.TokenEnv != "" && c.Cloudflare.TokenFile != "" {
		return fmt.Errorf("acme.cloudflare token_env and token_file are mutually exclusive")
	}
	if err = secureURL(c.DirectoryURL); err != nil {
		return fmt.Errorf("acme.directory_url: %w", err)
	}
	for name, value := range map[string]string{"propagation_timeout": c.PropagationTimeout} {
		d, err := time.ParseDuration(value)
		if err != nil || d < time.Second || d > 24*time.Hour {
			return fmt.Errorf("acme.%s must be between 1s and 24h", name)
		}
	}
	return nil
}

func secureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("must be an HTTPS URL without credentials or fragment")
	}
	return nil
}

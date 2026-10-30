// Package certificate manages ACME renewal and atomic TLS snapshots.
package certificate

import (
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

type CloudflareOptions struct {
	ZoneID    string
	TokenEnv  string
	TokenFile string
}

type Options struct {
	Domain             string
	Email              string
	AcceptTerms        bool
	DirectoryURL       string
	CacheDir           string
	PropagationTimeout time.Duration
	Cloudflare         CloudflareOptions
}

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var zoneID = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func (c Options) normalized() Options {
	c.Domain = strings.ToLower(strings.TrimSuffix(c.Domain, "."))
	if c.DirectoryURL == "" {
		c.DirectoryURL = acme.LetsEncryptURL
	}
	if c.CacheDir == "" {
		c.CacheDir = "acme"
	}
	if c.PropagationTimeout == 0 {
		c.PropagationTimeout = 2 * time.Minute
	}
	if c.Cloudflare.TokenEnv == "" && c.Cloudflare.TokenFile == "" {
		c.Cloudflare.TokenEnv = "CLOUDFLARE_API_TOKEN"
	}
	return c
}

// Validate 只校验结构，不读取凭据、不发起网络请求或创建缓存。
func (c Options) Validate() error {
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
	if c.PropagationTimeout < time.Second || c.PropagationTimeout > 24*time.Hour {
		return fmt.Errorf("证书传播等待时间应在 1 秒至 24 小时之间")
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

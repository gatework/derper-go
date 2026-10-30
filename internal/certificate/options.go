// Package certificate manages ACME renewal and atomic TLS snapshots.
package certificate

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/derper-go/internal/config"
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
	if err := config.ValidateDomain(c.Domain); err != nil {
		return err
	}
	email, err := mail.ParseAddress(c.Email)
	if err != nil || email.Address != c.Email {
		return fmt.Errorf("email：请填写有效的联系邮箱")
	}
	if !c.AcceptTerms {
		return fmt.Errorf("自动签发需要接受证书机构条款（--accept-terms）")
	}
	if c.Cloudflare.ZoneID != "" && !zoneID.MatchString(c.Cloudflare.ZoneID) {
		return fmt.Errorf("cloudflare.zone must be a 32-character hexadecimal zone ID")
	}
	if c.Cloudflare.TokenEnv != "" && c.Cloudflare.TokenFile != "" {
		return fmt.Errorf("不能同时指定 Cloudflare 凭据文件与环境变量")
	}
	if err = secureURL(c.DirectoryURL); err != nil {
		return fmt.Errorf("certificate.ca: %w", err)
	}
	if c.PropagationTimeout < time.Second || c.PropagationTimeout > 24*time.Hour {
		return fmt.Errorf("证书传播等待时间应在 1 秒至 24 小时之间")
	}

	return nil
}

func secureURL(raw string) error { return config.HTTPSURL(raw) }

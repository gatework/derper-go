// Package config describes operator intent without performing network discovery.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/gatework/derper-go/internal/fileio"
)

const (
	DefaultPath                = "/etc/derper-go/config.json"
	DefaultDataDir             = "/var/lib/derper-go"
	DefaultRuntimeDir          = "/run/derper-go"
	DefaultMaxConnections      = 2048
	DefaultMaxConcurrentChecks = 32
	DefaultPort                = 443
	AlternatePort              = 8443
	DefaultSTUNPort            = 3478
	DefaultRegion              = 900
	DefaultSocket              = "/run/tailscale/tailscaled.sock"
	ProductionCA               = "https://acme-v02.api.letsencrypt.org/directory"
	StagingCA                  = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Access string

const (
	Tailnet Access = "tailnet"
	Public  Access = "public"
)

// Config contains only user choices. A zero optional field selects its default.
type Config struct {
	Domain        string      `json:"domain"`
	Email         string      `json:"email,omitempty"`
	Port          int         `json:"port,omitempty"`
	Region        int         `json:"region,omitempty"`
	Access        Access      `json:"access,omitempty"`
	Certificate   Certificate `json:"certificate,omitzero"`
	DNS           DNS         `json:"dns,omitzero"`
	Relay         Relay       `json:"relay,omitzero"`
	Tailscale     Tailscale   `json:"tailscale,omitzero"`
	Cloudflare    Cloudflare  `json:"cloudflare,omitzero"`
	STUN          STUN        `json:"stun,omitzero"`
	CaptivePortal bool        `json:"captive_portal,omitempty"`
	LogLevel      string      `json:"log_level,omitempty"`
}
type Certificate struct {
	File string `json:"file,omitempty"`
	Key  string `json:"key,omitempty"`
	CA   string `json:"ca,omitempty"`
}
type DNS struct {
	Publish *bool  `json:"publish,omitempty"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
}
type Relay struct {
	MaxConnections int `json:"max_connections,omitempty"`
}
type Tailscale struct {
	Socket              string `json:"socket,omitempty"`
	MaxConcurrentChecks int    `json:"max_concurrent_checks,omitempty"`
}
type Cloudflare struct {
	Zone      string `json:"zone,omitempty"`
	TokenFile string `json:"token_file,omitempty"`
}
type STUN struct {
	Enabled *bool `json:"enabled,omitempty"`
	Port    int   `json:"port,omitempty"`
}

// Settings is a resolved value passed only to the composition layer.
type Settings struct {
	MaxConnections, MaxConcurrentChecks                                      int
	Domain, Email                                                            string
	Port, Region, STUNPort                                                   int
	Access                                                                   Access
	STUNEnabled, CaptivePortal, PublishDNS, AutoIPv4                         bool
	IPv4, IPv6                                                               netip.Addr
	CertificateFile, CertificateKey, CA, Socket, ZoneID, TokenFile, LogLevel string
}

func (s Settings) AutomaticCertificate() bool { return s.CertificateFile == "" }
func (s Settings) NeedsCloudflare() bool      { return s.AutomaticCertificate() || s.PublishDNS }

// FieldError identifies invalid input without echoing a supplied secret.
type FieldError struct{ Field, Message string }

func (e *FieldError) Error() string       { return e.Field + "：" + e.Message }
func invalid(field, message string) error { return &FieldError{field, message} }

func Load(path string) (Config, error) {
	b, err := fileio.ReadRegularFile(path, 1<<20)
	if err != nil {
		return Config{}, err
	}
	return Decode(b)
}
func Decode(b []byte) (Config, error) {
	var c Config
	if !utf8.Valid(b) {
		return c, errors.New("配置必须使用 UTF-8 编码")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(b))); err != nil {
		return c, fmt.Errorf("配置格式错误：%w", err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("配置字段错误：%w", err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("配置必须是单个 JSON 对象")
	}
	c.Domain = strings.ToLower(strings.TrimSuffix(c.Domain, "."))
	return c, c.Validate()
}

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var zone = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func ValidateDomain(domain string) error {
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return invalid("域名", "请填写完整域名，例如 relay.example.com")
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return invalid("域名", "需要域名，不能填写 IP 地址")
	}
	for part := range strings.SplitSeq(domain, ".") {
		if !label.MatchString(part) {
			return invalid("域名", "请使用有效的英文域名或 punycode，不支持通配符")
		}
	}
	return nil
}
func (c Config) Validate() error { _, err := c.Resolve("."); return err }
func (c Config) Resolve(base string) (Settings, error) {
	s := Settings{Domain: strings.ToLower(strings.TrimSuffix(c.Domain, ".")), Email: c.Email, Port: c.Port, Region: c.Region, Access: c.Access, STUNPort: c.STUN.Port, STUNEnabled: true, PublishDNS: true, CaptivePortal: c.CaptivePortal, CA: c.Certificate.CA, Socket: c.Tailscale.Socket, ZoneID: c.Cloudflare.Zone, LogLevel: c.LogLevel}
	s.MaxConnections, s.MaxConcurrentChecks = c.Relay.MaxConnections, c.Tailscale.MaxConcurrentChecks
	if s.MaxConnections == 0 {
		s.MaxConnections = DefaultMaxConnections
	}
	if s.MaxConcurrentChecks == 0 {
		s.MaxConcurrentChecks = DefaultMaxConcurrentChecks
	}
	if s.MaxConnections < 1 || s.MaxConnections > 60000 {
		return s, invalid("relay.max_connections", "连接上限应为 1–60000")
	}
	if s.MaxConcurrentChecks < 1 || s.MaxConcurrentChecks > 128 {
		return s, invalid("tailscale.max_concurrent_checks", "并行验证上限应为 1–128")
	}
	if err := ValidateDomain(s.Domain); err != nil {
		return s, err
	}
	if s.Port == 0 {
		s.Port = DefaultPort
	}
	if s.Region == 0 {
		s.Region = DefaultRegion
	}
	if s.STUNPort == 0 {
		s.STUNPort = DefaultSTUNPort
	}
	if s.Access == "" {
		s.Access = Tailnet
	}
	if s.Socket == "" {
		s.Socket = DefaultSocket
	}
	if s.LogLevel == "" {
		s.LogLevel = "info"
	}
	if c.STUN.Enabled != nil {
		s.STUNEnabled = *c.STUN.Enabled
	}
	if c.DNS.Publish != nil {
		s.PublishDNS = *c.DNS.Publish
	}
	if s.Port < 1 || s.Port > 65535 {
		return s, invalid("HTTPS 端口", "取值应为 1–65535")
	}
	if s.STUNPort < 1 || s.STUNPort > 65535 {
		return s, invalid("STUN 端口", "取值应为 1–65535")
	}
	if s.CaptivePortal && s.Port == 80 {
		return s, invalid("HTTP 探测", "80 端口不能同时用于 HTTPS")
	}
	if s.Region < 900 || s.Region > 999 {
		return s, invalid("中继区域", "请使用 900–999 的自定义区域编号")
	}
	if s.Access != Tailnet && s.Access != Public {
		return s, invalid("访问范围", "请选择 tailnet 或 public")
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return s, err
	}
	resolve := func(path string) string {
		if path != "" && !filepath.IsAbs(path) {
			return filepath.Join(abs, path)
		}
		return path
	}
	s.Socket = resolve(s.Socket)
	s.CertificateFile = resolve(c.Certificate.File)
	s.CertificateKey = resolve(c.Certificate.Key)
	s.TokenFile = resolve(c.Cloudflare.TokenFile)
	if s.TokenFile == "" {
		s.TokenFile = filepath.Join(abs, "cloudflare.token")
	}
	if (s.CertificateFile == "") != (s.CertificateKey == "") {
		return s, invalid("手动证书", "证书文件与私钥必须一起填写")
	}
	if !s.AutomaticCertificate() && c.Certificate.CA != "" {
		return s, invalid("证书", "手动证书不能同时指定自动签发机构")
	}
	switch s.CA {
	case "", "letsencrypt":
		s.CA = ProductionCA
	case "staging":
		s.CA = StagingCA
	}
	if err := HTTPSURL(s.CA); err != nil {
		return s, invalid("证书机构", err.Error())
	}
	if s.AutomaticCertificate() {
		address, err := mail.ParseAddress(s.Email)
		if err != nil || address.Address != s.Email {
			return s, invalid("邮箱", "自动证书需要有效的联系邮箱")
		}
	}
	if s.ZoneID != "" && !zone.MatchString(s.ZoneID) {
		return s, invalid("Cloudflare 区域", "Zone ID 应为 32 位十六进制值，留空可自动发现")
	}
	if c.DNS.IPv4 == "" || c.DNS.IPv4 == "auto" {
		s.AutoIPv4 = true
	} else if c.DNS.IPv4 != "off" {
		s.IPv4, err = Address(c.DNS.IPv4, true)
		if err != nil {
			return s, invalid("IPv4", err.Error())
		}
	}
	if c.DNS.IPv6 != "" {
		s.IPv6, err = Address(c.DNS.IPv6, false)
		if err != nil {
			return s, invalid("IPv6", err.Error())
		}
	}
	if s.PublishDNS && !s.AutoIPv4 && !s.IPv4.IsValid() && !s.IPv6.IsValid() {
		return s, invalid("DNS", "启用域名发布时至少需要一个地址族")
	}
	switch s.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return s, invalid("日志级别", "请选择 debug、info、warn 或 error")
	}
	return s, nil
}
func HTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("需要不含凭据或片段的 HTTPS 地址")
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func Address(s string, v4 bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Is4() != v4 || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return netip.Addr{}, errors.New("需要相应地址族的公网单播地址")
	}
	return a, nil
}

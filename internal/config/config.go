// Package config decodes and validates the public configuration without network I/O.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gatework/derper-go/internal/certmgr"
	"github.com/gatework/derper-go/internal/fileio"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

type Config struct {
	SchemaVersion int                      `json:"schema_version"`
	Hostname      string                   `json:"hostname"`
	Listen        string                   `json:"listen"`
	HTTPPort      int                      `json:"http_port"`
	StateDir      string                   `json:"state_dir"`
	NodeKeyFile   string                   `json:"node_key_file"`
	STUN          STUN                     `json:"stun"`
	Verification  Verification             `json:"verification"`
	TLS           TLS                      `json:"tls"`
	ACME          ACME                     `json:"acme"`
	Cloudflare    certmgr.CloudflareConfig `json:"cloudflare"`
	DNS           DNS                      `json:"dns"`
	Region        Region                   `json:"region"`
	LogLevel      string                   `json:"log_level"`
}
type STUN struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
}
type Verification struct {
	Mode   string `json:"mode"`
	Socket string `json:"socket"`
}
type TLS struct {
	Mode        string `json:"mode"`
	Certificate string `json:"certificate,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
}
type ACME struct {
	Email              string `json:"email"`
	AcceptTerms        bool   `json:"accept_terms"`
	DirectoryURL       string `json:"directory_url,omitempty"`
	PropagationTimeout string `json:"propagation_timeout"`
}
type DNS struct {
	Mode     string   `json:"mode"`
	IPv4     string   `json:"ipv4,omitempty"`
	IPv6     string   `json:"ipv6,omitempty"`
	IPv4URL  string   `json:"ipv4_url,omitempty"`
	TTL      int      `json:"ttl"`
	Interval Duration `json:"interval"`
}
type Region struct {
	ID   int    `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
	Node string `json:"node"`
}

func Default() Config {
	return Config{SchemaVersion: 1, Listen: ":8443", HTTPPort: -1, StateDir: "/var/lib/derper", STUN: STUN{true, ":3478"}, Verification: Verification{"tailscaled", "/run/tailscale/tailscaled.sock"}, TLS: TLS{Mode: "acme"}, ACME: ACME{PropagationTimeout: "2m"}, DNS: DNS{Mode: "off", TTL: 1, Interval: Duration(5 * time.Minute)}, Region: Region{ID: 900}, LogLevel: "info"}
}

func Load(path string) (Config, error) {
	b, err := fileio.ReadRegularFile(path, 1<<20)
	if err != nil {
		return Config{}, err
	}
	c, err := Decode(b)
	if err != nil {
		return c, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return c, err
	}
	base := filepath.Dir(abs)
	for _, p := range []*string{&c.StateDir, &c.NodeKeyFile, &c.TLS.Certificate, &c.TLS.PrivateKey, &c.Cloudflare.TokenFile, &c.Verification.Socket} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	if c.NodeKeyFile == "" {
		c.NodeKeyFile = filepath.Join(c.StateDir, "derper.key")
	}
	return c, c.Validate()
}

func Decode(b []byte) (Config, error) {
	c := Default()
	if !utf8.Valid(b) {
		return c, errors.New("configuration must be valid UTF-8")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(b))); err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("decode configuration: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, errors.New("expected exactly one JSON object")
	}
	c.Hostname = strings.ToLower(strings.TrimSuffix(c.Hostname, "."))
	if c.Region.Code == "" {
		c.Region.Code = strings.Split(c.Hostname, ".")[0]
	}
	if c.Region.Name == "" {
		c.Region.Name = c.Region.Code
	}
	if c.Region.Node == "" {
		c.Region.Node = c.Region.Code
	}
	return c, c.Validate()
}

// Reject duplicate (including case-alias) fields and null before typed decoding.
func uniqueJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("configuration values must not be null")
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				s = strings.ToLower(s)
				if seen[s] {
					return fmt.Errorf("duplicate configuration field %q", s)
				}
				seen[s] = true
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueJSON(d); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	return nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return errors.New("schema_version must be 1")
	}
	if c.StateDir == "" {
		return errors.New("state_dir is required")
	}
	// Reuse the existing domain/credential validation without performing I/O.
	cert := c.CertificateConfig()
	cert.Email = "validation@example.com"
	cert.AcceptTerms = true
	if err := cert.Validate(); err != nil {
		return err
	}
	if _, p, err := net.SplitHostPort(c.Listen); err != nil || !validPort(p) {
		return errors.New("listen must have a numeric port between 1 and 65535")
	}
	if c.STUN.Enabled {
		if _, p, err := net.SplitHostPort(c.STUN.Listen); err != nil || !validPort(p) {
			return errors.New("stun.listen must have a numeric port between 1 and 65535")
		}
	}
	if c.HTTPPort != -1 && (c.HTTPPort < 1 || c.HTTPPort > 65535) {
		return errors.New("http_port must be -1 or a valid port")
	}
	if _, p, _ := net.SplitHostPort(c.Listen); fmt.Sprint(c.HTTPPort) == p {
		return errors.New("http_port conflicts with TLS listen port")
	}
	if c.Verification.Mode != "tailscaled" && c.Verification.Mode != "none" {
		return errors.New("verification.mode must be tailscaled or none")
	}
	if c.Verification.Mode == "tailscaled" && c.Verification.Socket == "" {
		return errors.New("tailscaled socket is required")
	}
	switch c.TLS.Mode {
	case "acme":
		if c.TLS.Certificate != "" || c.TLS.PrivateKey != "" {
			return errors.New("manual certificate fields conflict with ACME mode")
		}
		if err := c.CertificateConfig().Validate(); err != nil {
			return err
		}
	case "manual":
		if c.TLS.Certificate == "" || c.TLS.PrivateKey == "" {
			return errors.New("manual TLS requires certificate and private_key")
		}
	default:
		return errors.New("tls.mode must be acme or manual")
	}
	if c.DNS.Mode != "off" && c.DNS.Mode != "observe" && c.DNS.Mode != "manage" {
		return errors.New("dns.mode must be off, observe or manage")
	}
	if c.DNS.IPv4 != "" {
		if _, err := Address(c.DNS.IPv4, true); err != nil {
			return err
		}
	}
	if c.DNS.IPv6 != "" {
		if _, err := Address(c.DNS.IPv6, false); err != nil {
			return err
		}
	}
	if c.DNS.IPv4 != "" && c.DNS.IPv4URL != "" {
		return errors.New("dns.ipv4 and ipv4_url are mutually exclusive")
	}
	if c.DNS.IPv4URL != "" {
		u, err := url.Parse(c.DNS.IPv4URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.New("dns.ipv4_url must be HTTPS without credentials or fragment")
		}
	}
	if c.DNS.Mode != "off" && c.DNS.IPv4 == "" && c.DNS.IPv6 == "" && c.DNS.IPv4URL == "" {
		return errors.New("DNS publishing requires an address or ipv4_url")
	}
	if c.DNS.TTL != 1 && (c.DNS.TTL < 60 || c.DNS.TTL > 86400) {
		return errors.New("dns.ttl must be 1 (automatic) or 60..86400")
	}
	if time.Duration(c.DNS.Interval) < time.Second || time.Duration(c.DNS.Interval) > 24*time.Hour {
		return errors.New("dns.interval must be between 1s and 24h")
	}
	if c.Region.ID < 900 || c.Region.ID > 65535 {
		return errors.New("region.id must be between 900 and 65535")
	}
	if c.Region.Code == "" || c.Region.Node == "" || c.Region.Name == "" {
		return errors.New("region names must not be empty")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("invalid log_level")
	}
	return nil
}

func validPort(s string) bool {
	n, err := net.LookupPort("tcp", s)
	return err == nil && fmt.Sprint(n) == s && n > 0 && n <= 65535
}
func Address(s string, v4 bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Is4() != v4 || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return netip.Addr{}, errors.New("DNS address must be a public unicast address of the requested family")
	}
	return a, nil
}
func (c Config) CertificateConfig() certmgr.Config {
	return certmgr.Config{Domain: c.Hostname, Email: c.ACME.Email, AcceptTerms: c.ACME.AcceptTerms, DirectoryURL: c.ACME.DirectoryURL, CacheDir: filepath.Join(c.StateDir, "acme"), PropagationTimeout: c.ACME.PropagationTimeout, Cloudflare: c.Cloudflare}
}

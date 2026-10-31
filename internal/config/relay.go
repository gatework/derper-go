package config

import (
	"math"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type TCP struct {
	Keepalive    *Duration `json:"keepalive,omitempty"`
	UserTimeout  *Duration `json:"user_timeout,omitempty"`
	WriteTimeout *Duration `json:"write_timeout,omitempty"`
}
type ConnectionRate struct {
	PerSecond float64 `json:"per_second,omitempty"`
	Burst     int     `json:"burst,omitempty"`
}
type HTTP struct {
	Port *int `json:"port,omitempty"`
}
type Admission struct {
	Mode                AdmissionMode `json:"mode,omitempty"`
	URL                 string        `json:"url,omitempty"`
	FailOpen            *bool         `json:"fail_open,omitempty"`
	Timeout             *Duration     `json:"timeout,omitempty"`
	MaxConcurrentChecks int           `json:"max_concurrent_checks,omitempty"`
	BlockedApps         []string      `json:"blocked_apps,omitempty"`
}
type Mesh struct {
	KeyFile string     `json:"key_file,omitempty"`
	Peers   []MeshPeer `json:"peers,omitempty"`
}
type MeshPeer struct {
	Host string `json:"host"`
	Dial string `json:"dial,omitempty"`
}
type BootstrapDNS struct {
	Names    []string        `json:"names,omitempty"`
	Unlisted []BootstrapName `json:"unlisted,omitempty"`
}
type BootstrapName struct {
	Name          string `json:"name"`
	RolloutRecord string `json:"rollout_record,omitempty"`
}

func (s Settings) HTTPSAddress() string { return net.JoinHostPort(s.ListenHost, strconv.Itoa(s.Port)) }
func (s Settings) STUNAddress() string {
	return net.JoinHostPort(s.ListenHost, strconv.Itoa(s.STUNPort))
}

func (c Config) resolveListen(s *Settings) error {
	if c.Relay.Listen == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(c.Relay.Listen)
	if err != nil {
		return invalid("relay.listen", "请使用 :443、127.0.0.1:8443 或 [::1]:8443")
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return invalid("relay.listen", "监听主机必须是 IP 地址，留空监听所有接口")
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return invalid("relay.listen", "端口应为 1–65535")
	}
	s.ListenHost, s.Port = host, number
	return nil
}

func (c Config) resolveAdvanced(s *Settings, base string) error {
	s.RelayEnabled = true
	if c.Relay.Enabled != nil {
		s.RelayEnabled = *c.Relay.Enabled
	}
	s.HTTPPort = -1
	if c.HTTP.Port != nil {
		s.HTTPPort = *c.HTTP.Port
	}
	if s.HTTPPort != -1 && (s.HTTPPort < 1 || s.HTTPPort > 65535) {
		return invalid("http.port", "使用 1–65535，或 -1 关闭 HTTP 探测")
	}
	if s.HTTPPort == s.Port {
		return invalid("http.port", "不能与 HTTPS 监听端口相同")
	}
	s.TCPKeepalive = durationValue(c.Relay.TCP.Keepalive, 10*time.Minute)
	s.TCPUserTimeout = durationValue(c.Relay.TCP.UserTimeout, 15*time.Second)
	s.TCPWriteTimeout = durationValue(c.Relay.TCP.WriteTimeout, 2*time.Second)
	for _, field := range []struct {
		name  string
		value time.Duration
	}{{"relay.tcp.keepalive", s.TCPKeepalive}, {"relay.tcp.user_timeout", s.TCPUserTimeout}, {"relay.tcp.write_timeout", s.TCPWriteTimeout}} {
		if field.value < 0 || field.value > 24*time.Hour || (field.value > 0 && field.value < time.Millisecond) {
			return invalid(field.name, "使用 1ms 至 24h；0s 表示关闭")
		}
	}
	s.ConnectionRate, s.ConnectionBurst = c.Relay.ConnectionRate.PerSecond, c.Relay.ConnectionRate.Burst
	if math.IsNaN(s.ConnectionRate) || math.IsInf(s.ConnectionRate, 0) || s.ConnectionRate < 0 || s.ConnectionRate > 100000 {
		return invalid("relay.connection_rate.per_second", "每秒连接数应为 0–100000，0 表示不限速")
	}
	if s.ConnectionBurst < 0 || s.ConnectionBurst > 60000 {
		return invalid("relay.connection_rate.burst", "突发额度应为 1–60000，留空自动选择")
	}
	if s.ConnectionRate == 0 && s.ConnectionBurst != 0 {
		return invalid("relay.connection_rate.burst", "请先设置 per_second 启用连接速率限制")
	}
	if s.ConnectionRate > 0 && s.ConnectionBurst == 0 {
		s.ConnectionBurst = min(60000, max(1, int(math.Ceil(s.ConnectionRate))))
	}
	s.Homepage = c.Relay.Homepage
	if s.Homepage != "" && s.Homepage != "blank" {
		if _, err := webURL(s.Homepage, false); err != nil {
			return invalid("relay.homepage", "使用 blank 或不含凭据、片段的 HTTP/HTTPS 跳转地址")
		}
	}
	s.AdmissionURL = c.Admission.URL
	s.AdmissionTimeout = durationValue(c.Admission.Timeout, 3*time.Second)
	if s.AdmissionTimeout < 100*time.Millisecond || s.AdmissionTimeout > 3*time.Second {
		return invalid("admission.timeout", "验证总预算应为 100ms 至 3s，包含排队时间")
	}
	if c.Admission.FailOpen != nil {
		s.AdmissionFailOpen = *c.Admission.FailOpen
	}
	if s.Access == Controller {
		if _, err := webURL(s.AdmissionURL, true); err != nil {
			return invalid("admission.url", "controller 准入模式需要 HTTPS 地址；本机回环服务也可使用 HTTP")
		}
	} else if s.AdmissionURL != "" || s.AdmissionFailOpen {
		return invalid("admission", "自定义准入服务需要 admission.mode 为 controller")
	}
	if len(c.Admission.BlockedApps) > 64 {
		return invalid("admission.blocked_apps", "最多设置 64 个应用名称")
	}
	seen := map[string]bool{}
	for _, name := range c.Admission.BlockedApps {
		if name == "" || len(name) > 128 || strings.TrimSpace(name) != name || strings.IndexFunc(name, unicode.IsControl) >= 0 || seen[name] {
			return invalid("admission.blocked_apps", "应用名称应非空、不重复，且不含首尾空白或控制字符")
		}
		seen[name] = true
		s.BlockedApps = append(s.BlockedApps, name)
	}
	s.MeshKeyFile = c.Mesh.KeyFile
	if s.MeshKeyFile != "" && !filepath.IsAbs(s.MeshKeyFile) {
		s.MeshKeyFile = filepath.Join(base, s.MeshKeyFile)
	}
	if len(c.Mesh.Peers) > 32 {
		return invalid("mesh.peers", "最多设置 32 个互联节点")
	}
	if len(c.Mesh.Peers) > 0 && s.MeshKeyFile == "" {
		return invalid("mesh.key_file", "节点互联需要共享密钥文件")
	}
	if !s.RelayEnabled && (s.MeshKeyFile != "" || len(c.Mesh.Peers) > 0) {
		return invalid("mesh", "关闭 DERP 时不能启用节点互联")
	}
	seen = map[string]bool{}
	for _, peer := range c.Mesh.Peers {
		if !validAuthority(peer.Host) || seen[peer.Host] {
			return invalid("mesh.peers.host", "使用不重复的域名或 IP，可附带端口；IPv6 使用方括号")
		}
		if peer.Dial != "" && !validAuthority(peer.Dial) {
			return invalid("mesh.peers.dial", "使用连接目的地的域名或 IP，可附带端口")
		}
		seen[peer.Host] = true
		s.MeshPeers = append(s.MeshPeers, peer)
	}
	if len(c.BootstrapDNS.Names)+len(c.BootstrapDNS.Unlisted) > 100 {
		return invalid("bootstrap_dns", "最多设置 100 个引导域名")
	}
	seen = map[string]bool{}
	normalize := func(name string) (string, error) {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if err := ValidateDomain(name); err != nil {
			return "", invalid("bootstrap_dns", "请填写完整域名，不使用通配符或 IP")
		}
		return name, nil
	}
	for _, name := range c.BootstrapDNS.Names {
		name, err := normalize(name)
		if err != nil {
			return err
		}
		if seen[name] {
			return invalid("bootstrap_dns", "引导域名不能重复")
		}
		seen[name] = true
		s.BootstrapNames = append(s.BootstrapNames, name)
	}
	for _, entry := range c.BootstrapDNS.Unlisted {
		name, err := normalize(entry.Name)
		if err != nil {
			return err
		}
		entry.Name = name
		if seen[name] {
			return invalid("bootstrap_dns", "公开与隐藏域名不能重复")
		}
		seen[name] = true
		if entry.RolloutRecord != "" {
			entry.RolloutRecord, err = normalize(entry.RolloutRecord)
			if err != nil {
				return err
			}
		}
		s.BootstrapUnlisted = append(s.BootstrapUnlisted, entry)
	}
	if !s.RelayEnabled && len(s.BootstrapNames)+len(s.BootstrapUnlisted) == 0 {
		return invalid("relay.enabled", "仅提供引导 DNS 时，至少设置一个 bootstrap_dns 域名")
	}
	return nil
}

func webURL(raw string, localHTTPOnly bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, invalid("URL", "需要不含凭据或片段的 HTTP/HTTPS 地址")
	}
	if localHTTPOnly && u.Scheme == "http" {
		host := u.Hostname()
		ip, e := netip.ParseAddr(host)
		if host != "localhost" && (e != nil || !ip.IsLoopback()) {
			return nil, invalid("URL", "远程准入控制器需要 HTTPS")
		}
	}
	return u, nil
}
func validAuthority(authority string) bool {
	if strings.HasSuffix(authority, ":") {
		return false
	}
	if authority == "" || strings.ContainsAny(authority, "/@?#\\") || strings.IndexFunc(authority, unicode.IsSpace) >= 0 {
		return false
	}
	u, err := url.Parse("https://" + authority)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return ValidateDomain(strings.ToLower(host)) == nil
}

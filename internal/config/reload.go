package config

import (
	"errors"
	"reflect"
	"sort"
	"strings"
)

// CheckReload rejects changes that need new listeners, background workers,
// credentials or admission backends. Validation never partially applies changes.
func CheckReload(old, next Settings) error {
	if old.UsesController() != next.UsesController() {
		return errors.New("增删准入控制器需要 service restart")
	}
	normalize := func(s Settings) Settings {
		s.MaxConnections, s.ConnectionBurst, s.ConnectionRate = 0, 0, 0
		s.Homepage, s.AdmissionURL, s.AdmissionFailOpen, s.AdmissionTimeout = "", "", false, 0
		if !s.AutomaticCertificate() {
			s.CertificateFile, s.CertificateKey = "manual", "manual"
		}
		return s
	}
	if !reflect.DeepEqual(normalize(old), normalize(next)) {
		return errors.New("此变更需要 service restart：" + strings.Join(ChangedFields(normalize(old), normalize(next)), ", "))
	}
	return nil
}

// ChangedFields reports domain-facing names, never values that may contain secrets.
func ChangedFields(old, next Settings) []string {
	paths := map[string]string{
		"ListenHost": "relay.listen", "Port": "relay.listen", "Homepage": "relay.homepage", "RelayEnabled": "relay.enabled", "ConnectionRate": "relay.connection_rate.per_second", "ConnectionBurst": "relay.connection_rate.burst", "MaxConnections": "relay.max_connections",
		"TCPKeepalive": "relay.tcp.keepalive", "TCPUserTimeout": "relay.tcp.user_timeout", "TCPWriteTimeout": "relay.tcp.write_timeout", "HTTPPort": "http.port",
		"AdmissionURL": "admission.url", "AdmissionFailOpen": "admission.fail_open", "AdmissionTimeout": "admission.timeout", "Access": "admission.mode", "MaxConcurrentChecks": "admission.max_concurrent_checks", "MaxAdmissionRequests": "admission.max_requests", "BlockedApps": "admission.blocked_apps",
		"MeshKeyFile": "mesh.key_file", "MeshPeers": "mesh.peers", "BootstrapNames": "bootstrap_dns.names", "BootstrapUnlisted": "bootstrap_dns.unlisted",
		"Domain": "domain", "Email": "email", "Region": "region", "STUNPort": "stun.port", "STUNEnabled": "stun.enabled", "PublishDNS": "dns.publish", "AutoIPv4": "dns.ipv4", "IPv4": "dns.ipv4", "IPv6": "dns.ipv6",
		"CertificateFile": "certificate.file", "CertificateKey": "certificate.key", "CA": "certificate.ca", "Socket": "tailscale.socket", "ZoneID": "cloudflare.zone", "TokenFile": "cloudflare.token_file", "LogLevel": "log_level",
	}
	a, b := reflect.ValueOf(old), reflect.ValueOf(next)
	seen := map[string]bool{}
	for i := 0; i < a.NumField(); i++ {
		if reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
			continue
		}
		field := a.Type().Field(i).Name
		path, ok := paths[field]
		if !ok {
			path = field
		}
		seen[path] = true
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

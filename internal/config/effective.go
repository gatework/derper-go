package config

import "time"

// Effective returns the same operator-facing schema with defaults and paths
// resolved, suitable for inspection and copying into a new configuration.
func (c Config) Effective(base string) (Config, error) {
	s, err := c.Resolve(base)
	if err != nil {
		return Config{}, err
	}
	c.Domain, c.Region, c.Admission.Mode = s.Domain, s.Region, s.Access
	c.Relay.Listen = s.HTTPSAddress()
	c.Relay.Enabled = &s.RelayEnabled
	c.Relay.MaxConnections = s.MaxConnections
	c.Relay.ConnectionRate = ConnectionRate{PerSecond: s.ConnectionRate, Burst: s.ConnectionBurst}
	ptr := func(d time.Duration) *Duration { value := Duration(d); return &value }
	c.Relay.TCP = TCP{Keepalive: ptr(s.TCPKeepalive), UserTimeout: ptr(s.TCPUserTimeout), WriteTimeout: ptr(s.TCPWriteTimeout)}
	c.HTTP.Port = &s.HTTPPort
	c.Admission.MaxConcurrentChecks = s.MaxConcurrentChecks
	c.Admission.Timeout = ptr(s.AdmissionTimeout)
	c.Admission.FailOpen = &s.AdmissionFailOpen
	c.Admission.BlockedApps = s.BlockedApps
	c.STUN.Enabled, c.STUN.Port = &s.STUNEnabled, s.STUNPort
	c.DNS.Publish = &s.PublishDNS
	if c.DNS.IPv4 == "" {
		c.DNS.IPv4 = "auto"
	}
	c.LogLevel = s.LogLevel
	if s.Access == Tailnet {
		c.Tailscale.Socket = s.Socket
	}
	if s.NeedsCloudflare() {
		c.Cloudflare.TokenFile = s.TokenFile
	}
	c.Certificate.File, c.Certificate.Key = s.CertificateFile, s.CertificateKey
	if s.AutomaticCertificate() && c.Certificate.CA == "" {
		c.Certificate.CA = "letsencrypt"
	}
	c.Mesh.KeyFile, c.Mesh.Peers = s.MeshKeyFile, s.MeshPeers
	c.BootstrapDNS.Names, c.BootstrapDNS.Unlisted = s.BootstrapNames, s.BootstrapUnlisted
	return c, nil
}

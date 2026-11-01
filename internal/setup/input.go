package setup

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/dns"
)

// Mode describes deployment intent; its zero value installs and starts the service.
type Mode uint8

const (
	StartService Mode = iota
	PrepareService
	PrepareForeground
)

// Overrides distinguishes an omitted setting from an explicitly supplied zero.
// It contains only the settings accepted by init; existing configuration is kept.
type Overrides struct {
	Domain, Email, Listen, AdmissionURL, IPv4, IPv6, Socket, CA *string
	CertificateFile, CertificateKey                             *string
	Region, HTTPPort                                            *int
	Admission                                                   *config.AdmissionMode
	PublishDNS, STUNEnabled                                     *bool
}

// Sources are optional input files, relative to the caller's working directory.
// On an existing deployment, explicit sources assert equality; omitted ones are ignored.
type Sources struct{ TokenFile, Identity, ImportCertificate, ImportKey string }

// Consent keeps installation approval separate from certificate authority terms.
type Consent struct{ Install, Terms bool }

// Request describes one invocation, without exposing mutable execution state.
type Request struct {
	ConfigPath, StateDir string
	Overrides            Overrides
	Sources              Sources
	Mode                 Mode
	Preview, Interactive bool
	Consent              Consent
}

// Need identifies missing operator input; credentials are requested lazily.
type Need uint8

const (
	Domain Need = iota
	Email
	CloudflareToken
)

func (n Need) String() string {
	switch n {
	case Domain:
		return "中继域名（--domain）"
	case Email:
		return "证书联系邮箱（--email）"
	case CloudflareToken:
		return "Cloudflare API Token"
	default:
		return "初始化输入"
	}
}

// Interaction supplies presentation and input; Initialize owns when each is used.
type Interaction interface {
	Read(context.Context, Need) (string, error)
	Show(Display)
	Confirm(context.Context, Confirmation) (Consent, error)
}

// Confirmation describes the scope of the single installation confirmation.
type Confirmation struct{ TermsRequired bool }
type DisplayKind uint8

const (
	InstallationSummary DisplayKind = iota
	ContinuingInstallation
	ResumingInstallation
)

type Display struct {
	Kind    DisplayKind
	Summary Summary
}

// Summary is a detached display value, never an executable plan or credential source.
type Summary struct {
	Domain, HTTPSAddress, ConfigPath, StateDir      string
	Admission                                       config.AdmissionMode
	Region                                          int
	ControllerURL                                   string
	ControllerFailOpen, MeshConfigured              bool
	MeshPeers                                       int
	ExistingListener, AlternatePort, Service, Start bool
	AutomaticCertificate                            bool
	CA, TermsURL                                    string
	Changes                                         []dns.Change
}

// Outcome selects presentation without exposing journal phase decisions to callers.
type Outcome uint8

const (
	ExistingDeployment Outcome = iota
	RunningDeployment
	PreviewedInstallation
	PreviewedDeployment
	ForegroundPrepared
	ServicePrepared
	MigrationStaged
	RelayReady
	BootstrapReady
)

type Result struct {
	Outcome                     Outcome
	ConfigPath, StateDir, Phase string
}

func (o Overrides) apply(c config.Config) (config.Config, error) {
	for _, v := range []struct {
		input  *string
		target *string
	}{
		{o.Domain, &c.Domain},
		{o.Email, &c.Email},
		{o.Listen, &c.Relay.Listen},
		{o.AdmissionURL, &c.Admission.URL},
		{o.IPv4, &c.DNS.IPv4},
		{o.IPv6, &c.DNS.IPv6},
		{o.Socket, &c.Tailscale.Socket},
		{o.CA, &c.Certificate.CA},
	} {
		if v.input != nil {
			*v.target = *v.input
		}
	}
	if o.Region != nil {
		c.Region = *o.Region
	}
	if o.HTTPPort != nil {
		v := *o.HTTPPort
		c.HTTP.Port = &v
	}
	if o.Admission != nil {
		c.Admission.Mode = *o.Admission
	}
	if o.PublishDNS != nil {
		v := *o.PublishDNS
		c.DNS.Publish = &v
	}
	if o.STUNEnabled != nil {
		v := *o.STUNEnabled
		c.STUN.Enabled = &v
	}
	for _, v := range []struct {
		input  *string
		target *string
	}{{o.CertificateFile, &c.Certificate.File}, {o.CertificateKey, &c.Certificate.Key}} {
		if v.input != nil {
			path, err := filepath.Abs(*v.input)
			if err != nil {
				return c, err
			}
			*v.target = path
		}
	}
	c.Domain = strings.ToLower(strings.TrimSuffix(c.Domain, "."))
	return c, nil
}

// Package daemon composes the relay and independent certificate/DNS lifecycles.
package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gatework/derper-go/internal/admission"
	"github.com/gatework/derper-go/internal/bootstrap"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/dns"
	"github.com/gatework/derper-go/internal/relay"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/systemd"
	"github.com/gatework/derper-go/internal/tailnet"
)

func CertificateOptions(s config.Settings, dir string) certificate.Options {
	credential := cloudflare.RuntimeCredentials(s.TokenFile)
	return certificate.Options{Domain: s.Domain, Email: s.Email, AcceptTerms: true, DirectoryURL: s.CA, CacheDir: filepath.Join(dir, "certificates"), Cloudflare: certificate.CloudflareOptions{ZoneID: s.ZoneID, TokenFile: credential.File}}
}
func NewDNSPublisher(s config.Settings, dir string, approved []cloudflare.Record) *dns.Publisher {
	client := cloudflare.NewSource(cloudflare.RuntimeCredentials(s.TokenFile).Read, s.ZoneID, nil)
	ipv4, ipv6 := "", ""
	if s.IPv4.IsValid() {
		ipv4 = s.IPv4.String()
	}
	if s.IPv6.IsValid() {
		ipv6 = s.IPv6.String()
	}
	return dns.New(dns.Options{Domain: s.Domain, StateDir: dir, IPv4: ipv4, IPv6: ipv6, AutoIPv4: s.AutoIPv4, Publish: s.PublishDNS, Approved: approved}, client)
}
func Check(s config.Settings) error {
	if s.MeshKeyFile != "" {
		if _, err := relay.LoadMeshKey(s.MeshKeyFile); err != nil {
			return err
		}
	}
	if !s.AutomaticCertificate() {
		_, err := certificate.Manual(s.Domain, s.CertificateFile, s.CertificateKey)
		return err
	}
	_, err := certificate.New(CertificateOptions(s, "."), nil, nil)
	return err
}

func Run(parent context.Context, s config.Settings, dir string, logger *slog.Logger) error {
	return run(parent, s, dir, "", nil, logger)
}
func RunFile(parent context.Context, s config.Settings, dir, path string, logger *slog.Logger) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	return run(parent, s, dir, path, signals, logger)
}
func run(parent context.Context, s config.Settings, dir, path string, signals <-chan os.Signal, logger *slog.Logger) (err error) {
	if err = Check(s); err != nil {
		return err
	}
	if s.AutomaticCertificate() {
		if err = state.CheckTerms(dir, s.Domain, s.CA); err != nil {
			return err
		}
	}
	store, err := state.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	identity, err := store.LoadOrCreateIdentity()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	health, err := newHealth(dir, s.Domain, logger)
	if err != nil {
		return err
	}
	defer func() { health.stop(err) }()
	var verifier *tailnet.Verifier
	var controller *admission.Controller
	var access relay.ClientVerifier
	if s.UsesController() {
		controller = admission.New(admission.Options{URL: s.AdmissionURL, FailOpen: s.AdmissionFailOpen, Timeout: s.AdmissionTimeout, MaxConcurrentChecks: s.MaxConcurrentChecks, MaxRequests: s.MaxAdmissionRequests})
		defer controller.Close()
		access = controller
	}
	if s.UsesTailnet() {
		verifier = tailnet.New(tailnet.Options{Socket: s.Socket, MaxConcurrentChecks: s.MaxConcurrentChecks, MaxRequests: s.MaxAdmissionRequests})
		defer verifier.Close()
		access = verifier
	}
	if verifier != nil && controller != nil {
		access = admission.All(s.MaxAdmissionRequests, verifier, controller)
	}
	var renewer *certificate.Renewer
	var get relay.CertificateSource
	if s.AutomaticCertificate() {
		renewer, err = certificate.New(CertificateOptions(s, dir), logger, nil)
		if err != nil {
			return err
		}
		defer renewer.Close()
		get = renewer.GetCertificate
	} else {
		get, err = certificate.Manual(s.Domain, s.CertificateFile, s.CertificateKey)
		if err != nil {
			return err
		}
	}
	live := &liveCertificate{}
	live.set(get)
	get = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return live.current.Load().get(hello) }
	opts := relay.Options{Disabled: !s.RelayEnabled, Homepage: s.Homepage, MaxConnections: s.MaxConnections, Domain: s.Domain, Listen: s.HTTPSAddress(), STUNEnabled: s.STUNEnabled, STUNListen: s.STUNAddress(), HTTPPort: s.HTTPPort, Verifier: access, AdmissionTimeout: s.AdmissionTimeout, BlockedApps: s.BlockedApps, ConnectionRate: s.ConnectionRate, ConnectionBurst: s.ConnectionBurst, TCP: &relay.TCPOptions{Keepalive: s.TCPKeepalive, UserTimeout: s.TCPUserTimeout, WriteTimeout: s.TCPWriteTimeout}}
	if s.MeshKeyFile != "" {
		secret, e := relay.LoadMeshKey(s.MeshKeyFile)
		if e != nil {
			return e
		}
		opts.Mesh = &relay.MeshOptions{Key: secret}
		for _, peer := range s.MeshPeers {
			opts.Mesh.Peers = append(opts.Mesh.Peers, relay.MeshPeer{Host: peer.Host, Dial: peer.Dial})
		}
	}
	var bootstrapDNS *bootstrap.Service
	if len(s.BootstrapNames)+len(s.BootstrapUnlisted) > 0 {
		options := bootstrap.Options{Names: s.BootstrapNames}
		for _, name := range s.BootstrapUnlisted {
			options.Unlisted = append(options.Unlisted, bootstrap.Name{Name: name.Name, RolloutRecord: name.RolloutRecord})
		}
		bootstrapDNS = bootstrap.New(options)
		opts.Bootstrap = bootstrapDNS
	}
	server, err := relay.Bind(ctx, opts, identity, get, logger)
	if err != nil {
		return err
	}
	defer server.Close()
	health.watch(server, verifier, controller, s)
	if renewer != nil {
		if err = renewer.Start(ctx); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		cancel()
		return <-done
	case <-server.Ready():
	}
	if err = health.ready(get); err != nil {
		cancel()
		<-done
		return err
	}
	if path != "" {
		current := s
		closeControl, e := startReloadControl(dir, func(ctx context.Context, preview bool) (ReloadPlan, error) {
			return reloadConfiguration(ctx, path, &current, server, controller, live, preview)
		}, logger, signals)
		if e != nil {
			cancel()
			<-done
			return e
		}
		defer closeControl()
	}
	message := "HTTPS 与 DERP 中继已就绪"
	if !s.RelayEnabled {
		message = "HTTPS 服务已就绪，DERP 已关闭"
	}
	if err = systemd.Notify("READY=1\nSTATUS=" + message); err != nil {
		cancel()
		<-done
		return err
	}
	logger.Info("中继已就绪", "domain", s.Domain, "port", s.Port, "access", s.Access)
	var workers sync.WaitGroup
	if bootstrapDNS != nil {
		workers.Go(func() { bootstrapDNS.Run(ctx, health.bootstrap) })
	}
	if s.PublishDNS {
		deployment, e := state.ReadDeployment(dir)
		if e != nil {
			logger.Debug("没有初始化 DNS 快照", "error", e)
		}
		workers.Go(func() {
			publisher := NewDNSPublisher(s, dir, deployment.ApprovedDNS)
			defer publisher.Close()
			publisher.Run(ctx, logger, health.dns)
		})
	} else {
		health.dnsDisabled()
	}
	workers.Go(func() { health.monitor(ctx, get, verifier, renewer) })
	err = <-done
	cancel()
	workers.Wait()
	if err != nil {
		return fmt.Errorf("中继监听失败：%w", err)
	}
	return nil
}

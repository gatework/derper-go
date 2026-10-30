// Package daemon composes the relay and independent certificate/DNS lifecycles.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"sync"

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
func DNS(s config.Settings, dir string, approved []cloudflare.Record) *dns.Publisher {
	client := cloudflare.NewSource(cloudflare.RuntimeCredentials(s.TokenFile).Read, s.ZoneID, cloudflare.HTTPClient())
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
	if !s.AutomaticCertificate() {
		_, err := certificate.Manual(s.Domain, s.CertificateFile, s.CertificateKey)
		return err
	}
	_, err := certificate.New(CertificateOptions(s, "."), nil, nil)
	return err
}

func Run(parent context.Context, s config.Settings, dir string, logger *slog.Logger) (err error) {
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
	health, err := newHealth(dir, s.Domain)
	if err != nil {
		return err
	}
	health.logger = logger
	defer func() { health.stop(err) }()
	var verifier *tailnet.Verifier
	if s.Access == config.Tailnet {
		verifier = tailnet.New(s.Socket)
		defer verifier.Close()
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
	opts := relay.Options{Domain: s.Domain, Listen: net.JoinHostPort("", strconv.Itoa(s.Port)), STUNEnabled: s.STUNEnabled, STUNListen: net.JoinHostPort("", strconv.Itoa(s.STUNPort)), HTTPPort: -1}
	if verifier != nil {
		opts.Verifier = verifier
	}
	if s.CaptivePortal {
		opts.HTTPPort = 80
	}
	server, err := relay.Bind(ctx, opts, identity, get, logger)
	if err != nil {
		return err
	}
	defer server.Close()
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
	if err = systemd.Notify("READY=1\nSTATUS=TLS 与 DERP 中继已就绪"); err != nil {
		cancel()
		<-done
		return err
	}
	logger.Info("中继已就绪", "domain", s.Domain, "port", s.Port, "access", s.Access)
	var workers sync.WaitGroup
	if s.PublishDNS {
		deployment, e := state.ReadDeployment(dir)
		if e != nil {
			logger.Debug("没有初始化 DNS 快照", "error", e)
		}
		workers.Go(func() { DNS(s, dir, deployment.ApprovedDNS).Run(ctx, logger, health.dns) })
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

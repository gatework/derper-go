// Package app owns the process lifetime and composes independent controllers.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gatework/derper-go/internal/certmgr"
	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/dns"
	"github.com/gatework/derper-go/internal/relay"
	"github.com/gatework/derper-go/internal/state"
)

func HTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not allowed") }}
}
func DNS(c config.Config) *dns.Controller {
	client := HTTPClient()
	return &dns.Controller{Config: c, HTTP: client, API: cloudflare.NewSource(func() (string, error) { return certmgr.Token(c.Cloudflare) }, c.Cloudflare.ZoneID, client)}
}

// Credentials resolves the systemd per-service credential directory at runtime.
func Credentials(c config.Config) config.Config {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && (c.TLS.Mode == "acme" || c.DNS.Mode != "off") {
		c.Cloudflare.TokenFile = filepath.Join(dir, "cloudflare-token")
		c.Cloudflare.TokenEnv = ""
	}
	return c
}

func Check(c config.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.TLS.Mode == "manual" {
		_, err := certmgr.Manual(c.Hostname, c.TLS.Certificate, c.TLS.PrivateKey)
		return err
	}
	return nil
}

func Run(parent context.Context, c config.Config, logger *slog.Logger) error {
	if err := Check(c); err != nil {
		return err
	}
	c = Credentials(c)
	lock, err := state.Acquire(c.StateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	identity, err := state.Identity(c.NodeKeyFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var manager *certmgr.Manager
	var certificate relay.CertificateSource
	if c.TLS.Mode == "acme" {
		manager, err = certmgr.New(c.CertificateConfig(), logger, nil)
		if err != nil {
			return err
		}
		defer manager.Close()
		certificate = manager.GetCertificate
	} else {
		certificate, err = certmgr.Manual(c.Hostname, c.TLS.Certificate, c.TLS.PrivateKey)
		if err != nil {
			return err
		}
	}
	server, err := relay.Bind(ctx, c, identity, certificate, logger)
	if err != nil {
		return err
	}
	defer server.Close()
	if manager != nil {
		if err = manager.Start(ctx); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return nil
	}
	var workers sync.WaitGroup
	if c.DNS.Mode != "off" {
		workers.Add(1)
		go func() { defer workers.Done(); DNS(c).Run(ctx, logger) }()
	}
	logger.Info("relay ready", "listen", server.Addr(), "stun", server.STUNAddr(), "hostname", c.Hostname, "verification", c.Verification.Mode, "dns_mode", c.DNS.Mode)
	err = server.Serve(ctx)
	cancel()
	workers.Wait()
	return err
}

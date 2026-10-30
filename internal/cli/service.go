package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/gatework/derper-go/internal/config"
)

func unitPath(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "%$\\\"") || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return "", errors.New("systemd paths must be absolute and contain no control characters, percent, dollar, backslash or quotes")
	}
	return strconv.Quote(path), nil
}
func renderUnit(binary, path string, c config.Config) (string, error) {
	b, err := unitPath(binary)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p, err := unitPath(abs)
	if err != nil {
		return "", err
	}
	if c.StateDir != "/var/lib/derper" {
		return "", errors.New("systemd deployment requires state_dir=/var/lib/derper")
	}
	dependency := ""
	if c.Verification.Mode == "tailscaled" {
		dependency = " tailscaled.service"
	}
	credential := ""
	if c.TLS.Mode == "acme" || c.DNS.Mode != "off" {
		if c.Cloudflare.TokenFile == "" {
			return "", errors.New("systemd deployment requires cloudflare.token_file")
		}
		if _, err := unitPath(c.Cloudflare.TokenFile); err != nil {
			return "", err
		}
		credential = "LoadCredential=" + strconv.Quote("cloudflare-token:"+c.Cloudflare.TokenFile) + "\n"
	}
	capability := "CapabilityBoundingSet=\n"
	_, port, _ := net.SplitHostPort(c.Listen)
	n, _ := strconv.Atoi(port)
	lowPort := n > 0 && n < 1024 || c.HTTPPort > 0 && c.HTTPPort < 1024
	if c.STUN.Enabled {
		_, p, _ := net.SplitHostPort(c.STUN.Listen)
		n, _ := strconv.Atoi(p)
		lowPort = lowPort || n > 0 && n < 1024
	}
	if lowPort {
		capability = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
	}
	return fmt.Sprintf(`[Unit]
Description=DERP and STUN relay with managed ACME certificates
Wants=network-online.target%s
After=network-online.target%s
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=derper
Group=derper
ExecStart=%s server --config %s
%sStateDirectory=derper
StateDirectoryMode=0700
UMask=0077
Environment=GOMEMLIMIT=96MiB
Restart=on-failure
RestartSec=30
TimeoutStopSec=45
LimitNOFILE=65536
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
%s
[Install]
WantedBy=multi-user.target
`, dependency, dependency, b, p, credential, capability), nil
}

func installUnit(ctx context.Context, unit string, force bool) error {
	if os.Geteuid() != 0 {
		return errors.New("service install requires root")
	}
	if _, err := user.Lookup("derper"); err != nil {
		return errors.New("create the derper system user first; see deployment documentation")
	}
	if err := writeExclusive("/etc/systemd/system/derper-go.service", []byte(unit), force); err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd reload failed: %w: %s", err, output)
	}
	return nil
}

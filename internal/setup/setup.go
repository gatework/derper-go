// Package setup turns a read-only deployment plan into resumable installation work.
package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/daemon"
	"github.com/gatework/derper-go/internal/dns"
	"github.com/gatework/derper-go/internal/fileio"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/systemd"
	"github.com/gatework/derper-go/internal/tailnet"
)

type Request struct {
	Config         config.Config
	Path, StateDir string
	Token          string
	Service, Start bool
}
type Plan struct {
	Config                   config.Config
	Settings                 config.Settings
	Path, StateDir, TermsURL string
	Changes                  []dns.Change
	AlternatePort            bool
	Service, Start           bool
	token                    string
	original                 []byte
}

// Workflow's dependencies are private; tests replace only host/network boundaries.
type Workflow struct {
	checkHost     func() error
	checkTailnet  func(context.Context, string, int) (int, error)
	portAvailable func(context.Context, int) bool
	discoverIPv4  func(context.Context) (string, error)
	dnsPlan       func(context.Context, config.Settings, string, string) ([]dns.Change, error)
	terms         func(context.Context, string) (string, error)
	install       func(context.Context, string, config.Settings) error
	start         func(context.Context) error
	wait          func(context.Context, string, config.Settings) error
	ownState      func(string) error
}

func New() *Workflow {
	return &Workflow{checkHost: systemd.Check, checkTailnet: inspectTailnet, portAvailable: portAvailable, discoverIPv4: dns.DiscoverIPv4, dnsPlan: inspectDNS, terms: discoverTerms, install: systemd.Install, start: func(ctx context.Context) error { return systemd.Control(ctx, "start") }, ownState: systemd.OwnStateFile, wait: WaitReady}
}
func inspectTailnet(ctx context.Context, socket string, region int) (int, error) {
	v := tailnet.New(socket)
	defer v.Close()
	if err := v.Check(ctx); err != nil {
		return 0, err
	}
	return v.Region(ctx, region)
}
func portAvailable(ctx context.Context, port int) bool {
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	l.Close()
	return true
}
func inspectDNS(ctx context.Context, s config.Settings, dir, token string) ([]dns.Change, error) {
	api := cloudflare.NewSource(func() (string, error) { return token, nil }, s.ZoneID, cloudflare.HTTPClient())
	if err := api.CheckZone(ctx, s.Domain); err != nil {
		return nil, err
	}
	if !s.PublishDNS {
		return nil, nil
	}
	ipv4, ipv6 := "", ""
	if s.IPv4.IsValid() {
		ipv4 = s.IPv4.String()
	}
	if s.IPv6.IsValid() {
		ipv6 = s.IPv6.String()
	}
	return dns.New(dns.Options{Domain: s.Domain, StateDir: dir, Publish: true, IPv4: ipv4, IPv6: ipv6}, api).Plan(ctx)
}
func discoverTerms(ctx context.Context, ca string) (string, error) {
	directory, err := (&acme.Client{DirectoryURL: ca, HTTPClient: cloudflare.HTTPClient()}).Discover(ctx)
	if err != nil {
		return "", fmt.Errorf("读取证书机构服务条款：%w", err)
	}
	if directory.Terms == "" {
		return ca, nil
	}
	if err = config.HTTPSURL(directory.Terms); err != nil {
		return "", err
	}
	return directory.Terms, nil
}
func Resolve(c config.Config, path string) (config.Settings, error) {
	s, err := c.Resolve(filepath.Dir(path))
	if err != nil {
		return s, err
	}
	if s.TokenFile == "" {
		s.TokenFile = filepath.Join(filepath.Dir(path), "cloudflare.token")
	}
	return s, nil
}
func DataDir(path string) string {
	if path == config.DefaultPath {
		return config.DefaultDataDir
	}
	return filepath.Join(filepath.Dir(path), "state")
}
func (w *Workflow) Prepare(ctx context.Context, r Request) (Plan, error) {
	p := Plan{Config: r.Config, Path: r.Path, StateDir: r.StateDir, Service: r.Service, Start: r.Start, token: r.Token}
	var err error
	if err = ctx.Err(); err != nil {
		return p, err
	}
	if r.Service {
		if r.Path != config.DefaultPath || r.StateDir != config.DefaultDataDir {
			return p, errors.New("系统服务使用标准配置和状态目录；其他位置请选择 --no-service")
		}
		if err = w.checkHost(); err != nil {
			return p, err
		}
	}
	p.original, err = fileio.ReadRegularFile(p.Path, 1<<20)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return p, err
	}
	p.Settings, err = Resolve(p.Config, p.Path)
	if err != nil {
		return p, err
	}
	if p.Settings.Access == config.Tailnet {
		id, e := w.checkTailnet(ctx, p.Settings.Socket, p.Config.Region)
		if e != nil {
			return p, e
		}
		if id != config.DefaultRegion {
			p.Config.Region = id
		}
	}
	if !w.portAvailable(ctx, p.Settings.Port) {
		if p.Config.Port != 0 || !w.portAvailable(ctx, config.AlternatePort) {
			return p, fmt.Errorf("HTTPS 端口 %d 已被占用，请指定可用的 --port", p.Settings.Port)
		}
		p.Config.Port = config.AlternatePort
		p.AlternatePort = true
	}
	p.Settings, err = Resolve(p.Config, p.Path)
	if err != nil {
		return p, err
	}
	if !p.Settings.AutomaticCertificate() {
		if _, err = certificate.Manual(p.Settings.Domain, p.Settings.CertificateFile, p.Settings.CertificateKey); err != nil {
			return p, err
		}
	}
	if p.Settings.NeedsCloudflare() {
		p.token, err = cloudflare.ValidateToken(p.token)
		if err != nil {
			return p, err
		}
		if p.Settings.PublishDNS && p.Settings.AutoIPv4 {
			v4, e := w.discoverIPv4(ctx)
			if e != nil {
				return p, e
			}
			p.Settings.IPv4, err = config.Address(v4, true)
			if err != nil {
				return p, err
			}
		}
		p.Changes, err = w.dnsPlan(ctx, p.Settings, p.StateDir, p.token)
		if err != nil {
			return p, err
		}
	}
	if p.Settings.AutomaticCertificate() {
		p.TermsURL, err = w.terms(ctx, p.Settings.CA)
		if err != nil {
			return p, err
		}
	}
	return p, nil
}
func ConfigBytes(c config.Config) ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	return append(b, '\n'), err
}
func Hash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func safeDirectory(path string) error {
	// Check each existing ancestor before MkdirAll, so a symlink cannot redirect
	// ownership or credential writes into another deployment.
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return fmt.Errorf("安装目录不是普通目录：%s", p)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return os.MkdirAll(path, 0700)
}

// Apply is called only after one explicit summary confirmation. Terms acceptance
// is a separate fact in automation, never implied by --yes.
func (w *Workflow) Apply(ctx context.Context, p Plan, acceptedTerms bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Settings.AutomaticCertificate() && !acceptedTerms {
		return errors.New("尚未接受证书机构服务条款；自动化需要 --accept-terms")
	}
	if err := safeDirectory(filepath.Dir(p.Path)); err != nil {
		return err
	}
	installation, err := state.Open(filepath.Dir(p.Path))
	if err != nil {
		return fmt.Errorf("另一初始化进程正在工作：%w", err)
	}
	defer installation.Close()
	if err = safeDirectory(p.StateDir); err != nil {
		return err
	}
	store, err := state.Open(p.StateDir)
	if err != nil {
		return err
	}
	// The daemon must acquire the same lock; release it before systemctl start.
	locked := true
	defer func() {
		if locked {
			store.Close()
		}
	}()
	existing, readErr := fileio.ReadRegularFile(p.Path, 1<<20)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if string(existing) != string(p.original) {
		return errors.New("配置在确认后已发生变化，请重新执行 init")
	}
	// The managed token always has one fixed path; input token files are sources.
	p.Config.Cloudflare.TokenFile = ""
	p.Settings.TokenFile = filepath.Join(filepath.Dir(p.Path), "cloudflare.token")
	if p.Service && !p.Settings.AutomaticCertificate() {
		for _, item := range []struct {
			source string
			target *string
			name   string
		}{{p.Settings.CertificateFile, &p.Config.Certificate.File, "certificate.pem"}, {p.Settings.CertificateKey, &p.Config.Certificate.Key, "certificate.key"}} {
			if item.source != filepath.Join(filepath.Dir(p.Path), item.name) {
				b, e := fileio.ReadRegularFile(item.source, 1<<20)
				if e != nil {
					return e
				}
				target := filepath.Join(filepath.Dir(p.Path), item.name)
				if info, e := os.Lstat(target); e == nil {
					if !info.Mode().IsRegular() {
						return errors.New("手动证书目标必须是普通文件")
					}
					previous, e := fileio.ReadRegularFile(target, 1<<20)
					if e != nil {
						return e
					}
					if !bytes.Equal(b, previous) {
						return errors.New("已有手动证书与本次来源不同，拒绝覆盖")
					}
				} else if !errors.Is(e, os.ErrNotExist) {
					return e
				} else if e = state.WriteFile(target, b, 0600, true); e != nil {
					return e
				}

			}
			*item.target = item.name
		}
		p.Settings, err = Resolve(p.Config, p.Path)
		if err != nil {
			return err
		}
	}
	b, err := ConfigBytes(p.Config)
	if err != nil {
		return err
	}
	journal, err := state.ReadDeployment(p.StateDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && journal.ConfigHash != Hash(b) {
		return errors.New("未完成安装的配置与本次选择不同，请恢复原配置后重试")
	}
	if journal.Phase == "ready" || journal.Phase == "prepared" {
		return nil
	}
	journal = state.Deployment{Domain: p.Settings.Domain, ConfigHash: Hash(b), Config: b, Phase: "approved"}
	if acceptedTerms && p.Settings.AutomaticCertificate() {
		journal.AcceptedCA = p.Settings.CA
		journal.AcceptedAt = time.Now().UTC()
	}
	for _, change := range p.Changes {
		if change.Action == "adopt" && change.Before != nil {
			journal.ApprovedDNS = append(journal.ApprovedDNS, *change.Before)
		}
	}
	if err = state.SaveDeployment(p.StateDir, journal); err != nil {
		return err
	}
	if p.Settings.NeedsCloudflare() {
		if err = state.Write(p.Settings.TokenFile, []byte(p.token+"\n")); err != nil {
			return err
		}
	}
	if err = state.Write(p.Path, b); err != nil {
		return err
	}
	if _, err = store.LoadOrCreateIdentity(); err != nil {
		return err
	}
	if p.Service {
		if err = w.install(ctx, p.Path, p.Settings); err != nil {
			return err
		}
	}
	journal.Phase = "prepared"
	if err = state.SaveDeployment(p.StateDir, journal); err != nil {
		return err
	}
	// Saving after chown creates root-owned setup.json; retain service readability.
	if p.Service {
		if err = w.ownState(filepath.Join(p.StateDir, "setup.json")); err != nil {
			return err
		}
	}
	if err = store.Close(); err != nil {
		return err
	}
	locked = false
	if !p.Service || !p.Start {
		return nil
	}
	if err = w.start(ctx); err != nil {
		return err
	}
	if err = w.wait(ctx, p.StateDir, p.Settings); err != nil {
		return err
	}
	journal.Phase = "ready"
	if err = state.SaveDeployment(p.StateDir, journal); err != nil {
		return err
	}
	if p.Service {
		return w.ownState(filepath.Join(p.StateDir, "setup.json"))
	}
	return nil
}
func WaitReady(ctx context.Context, dir string, s config.Settings) error {
	ctx, cancel := context.WithTimeout(ctx, 16*time.Minute)
	defer cancel()
	var last daemon.Status
	for {
		status, err := daemon.ReadStatus(dir)
		if err == nil {
			last = status
			if status.Active && status.Ready {
				if s.PublishDNS && status.DNS.State == "degraded" {
					return fmt.Errorf("中继已运行，但 DNS 发布失败：%s；修复后会自动重试", status.DNS.Detail)
				}
				if s.Access == config.Tailnet && status.Tailnet.State == "degraded" {
					return fmt.Errorf("中继已运行，但 Tailnet 检查失败：%s", status.Tailnet.Detail)
				}
				if (!s.PublishDNS || status.DNS.State == "ready") && (s.Access != config.Tailnet || status.Tailnet.State == "ready") {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("等待中继就绪超时或被取消（%s）；请运行 status 和 service logs：%w", last.Error, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

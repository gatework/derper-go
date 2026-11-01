// Package setup owns relay initialization, from read-only inspection to recovery.
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

type preparation struct {
	Config                                     config.Config
	Path, StateDir                             string
	Token                                      string
	Service, Start                             bool
	IdentityPath, ImportCertificate, ImportKey string
}
type plan struct {
	Config                       config.Config
	Settings                     config.Settings
	Path, StateDir, TermsURL     string
	Changes                      []dns.Change
	AlternatePort                bool
	Service, Start               bool
	token                        string
	original                     []byte
	identity                     []byte
	importCertificate, importKey string
	ExistingListener             bool
}

type deploymentPaths struct{ config, state string }

// Workflow owns initialization; dependencies and the executable plan stay private.
// Tests replace host/network boundaries and use a temporary deployment layout.
type Workflow struct {
	paths                deploymentPaths
	refresh              func(context.Context, config.Settings) error
	checkHost            func() error
	checkTailnet         func(context.Context, string, int) (int, error)
	portAvailable        func(context.Context, string, int) bool
	stunAvailable        func(context.Context, string, int) bool
	discoverIPv4         func(context.Context) (string, error)
	dnsPlan              func(context.Context, config.Settings, string, string) ([]dns.Change, error)
	terms                func(context.Context, string) (string, error)
	install              func(context.Context, string, config.Settings) error
	start                func(context.Context) error
	wait                 func(context.Context, string, config.Settings) error
	ownState             func(string) error
	stage                func(context.Context, string, config.Settings) error
	checkMigrationRegion func(context.Context, config.Settings) error
	checkRelayIdentity   func(context.Context, config.Settings, []byte) error
}

func New() *Workflow {
	return &Workflow{
		paths:                deploymentPaths{config: config.DefaultPath, state: config.DefaultDataDir},
		checkHost:            systemd.Check,
		checkTailnet:         inspectTailnet,
		portAvailable:        portAvailable,
		stunAvailable:        stunAvailable,
		discoverIPv4:         dns.DiscoverIPv4,
		dnsPlan:              inspectDNS,
		terms:                discoverTerms,
		install:              systemd.Install,
		stage:                systemd.Stage,
		refresh:              systemd.Refresh,
		start:                func(ctx context.Context) error { return systemd.Control(ctx, "start") },
		wait:                 WaitReady,
		ownState:             systemd.OwnStateFile,
		checkMigrationRegion: inspectMigrationRegion,
		checkRelayIdentity:   inspectRelayIdentity,
	}
}
func inspectTailnet(ctx context.Context, socket string, region int) (int, error) {
	v := tailnet.New(tailnet.Options{Socket: socket})
	defer v.Close()
	if err := v.Check(ctx); err != nil {
		return 0, err
	}
	return v.Region(ctx, region)
}
func portAvailable(ctx context.Context, host string, port int) bool {
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	l.Close()
	return true
}
func stunAvailable(ctx context.Context, host string, port int) bool {
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
func inspectDNS(ctx context.Context, s config.Settings, dir, token string) ([]dns.Change, error) {
	api := cloudflare.NewSource(func() (string, error) { return token, nil }, s.ZoneID, nil)
	defer api.Close()
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
	httpClient := cloudflare.HTTPClient()
	defer httpClient.CloseIdleConnections()
	directory, err := (&acme.Client{DirectoryURL: ca, HTTPClient: httpClient}).Discover(ctx)
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
	return c.Resolve(filepath.Dir(path))
}
func DataDir(path string) string {
	if path == config.DefaultPath {
		return config.DefaultDataDir
	}
	return filepath.Join(filepath.Dir(path), "state")
}
func (w *Workflow) prepare(ctx context.Context, r preparation) (plan, error) {
	p := plan{Config: r.Config, Path: r.Path, StateDir: r.StateDir, Service: r.Service, Start: r.Start, token: r.Token}
	var err error
	if err = ctx.Err(); err != nil {
		return p, err
	}
	if r.Service {
		if r.Path != w.paths.config || r.StateDir != w.paths.state {
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
	if r.IdentityPath != "" {
		if !p.Settings.UsesTailnet() || r.Config.Region == 0 || r.Start {
			return p, errors.New("身份迁移需要 Tailnet 模式、明确 region 和 --no-start")
		}
		p.identity, err = fileio.ReadRegularFile(r.IdentityPath, 16<<10)
		if err != nil {
			return p, errors.New("无法读取原 DERP 身份文件")
		}
		if _, err = state.DecodeIdentity(p.identity); err != nil {
			return p, err
		}
		if err = w.checkMigrationRegion(ctx, p.Settings); err != nil {
			return p, err
		}
	} else if p.Settings.UsesTailnet() {
		id, e := w.checkTailnet(ctx, p.Settings.Socket, p.Config.Region)
		if e != nil {
			return p, e
		}
		if id != config.DefaultRegion {
			p.Config.Region = id
		}
	}
	if !w.portAvailable(ctx, p.Settings.ListenHost, p.Settings.Port) {
		if len(p.identity) > 0 {
			if err = w.checkRelayIdentity(ctx, p.Settings, p.identity); err != nil {
				return p, err
			}
			p.ExistingListener = true
		} else if p.Config.Relay.Listen != "" || !w.portAvailable(ctx, p.Settings.ListenHost, config.AlternatePort) {
			return p, fmt.Errorf("HTTPS 端口 %d 不可用，请指定可用的 --listen", p.Settings.Port)
		}
		if !p.ExistingListener {
			p.Config.Relay.Listen = net.JoinHostPort(p.Settings.ListenHost, strconv.Itoa(config.AlternatePort))
			p.AlternatePort = true
		}
	}
	p.Settings, err = Resolve(p.Config, p.Path)
	if err != nil {
		return p, err
	}
	if p.Settings.STUNEnabled && !w.stunAvailable(ctx, p.Settings.ListenHost, p.Settings.STUNPort) {
		return p, fmt.Errorf("STUN UDP 端口 %d 不可用", p.Settings.STUNPort)
	}
	if p.Settings.HTTPPort > 0 && !w.portAvailable(ctx, p.Settings.ListenHost, p.Settings.HTTPPort) {
		return p, fmt.Errorf("HTTP 探测端口 %d 不可用", p.Settings.HTTPPort)
	}
	if p.Service {
		// Validate the credential path that apply will manage, before any writes.
		serviceSettings := p.Settings
		serviceSettings.TokenFile = filepath.Join(filepath.Dir(p.Path), "cloudflare.token")
		if _, err = systemd.Render(systemd.Binary, p.Path, serviceSettings); err != nil {
			return p, err
		}
	}
	if (r.ImportCertificate == "") != (r.ImportKey == "") {
		return p, errors.New("导入缓存证书需要同时指定 --import-certificate 与 --import-key")
	}
	if r.ImportCertificate != "" {
		if !p.Settings.AutomaticCertificate() {
			return p, errors.New("手动证书模式不能同时导入自动证书缓存")
		}
		if _, err = certificate.Manual(p.Settings.Domain, r.ImportCertificate, r.ImportKey); err != nil {
			return p, err
		}
		p.importCertificate, p.importKey = r.ImportCertificate, r.ImportKey
	}
	if err = daemon.Check(p.Settings); err != nil {
		return p, err
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

// apply is called only after one explicit summary confirmation. Terms acceptance
// is a separate fact in automation, never implied by --yes.
func (w *Workflow) apply(ctx context.Context, p plan, acceptedTerms bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Settings.AutomaticCertificate() && !acceptedTerms {
		return errors.New("尚未接受证书机构服务条款；自动化需要 --accept-terms")
	}
	if err := safeDirectory(filepath.Dir(p.Path)); err != nil {
		return err
	}
	installation, err := state.AcquireInstallation(filepath.Dir(p.Path))
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
	if len(p.identity) > 0 {
		target := filepath.Join(p.StateDir, "identity.json")
		existing, e := fileio.ReadRegularFile(target, 16<<10)
		if e == nil {
			oldKey, oldErr := state.DecodeIdentity(existing)
			newKey, _ := state.DecodeIdentity(p.identity)
			if oldErr != nil || !oldKey.Equal(newKey) {
				return errors.New("已有节点身份与导入身份不同，拒绝覆盖")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else if err = state.WriteFile(target, p.identity, 0600, true); err != nil {
			return err
		}
	}
	// The managed token always has one fixed path; input token files are sources.
	p.Config.Cloudflare.TokenFile = ""
	p.Settings.TokenFile = filepath.Join(filepath.Dir(p.Path), "cloudflare.token")
	var copies []certificateCopy
	if p.Service && !p.Settings.AutomaticCertificate() {
		copies = []certificateCopy{{p.Settings.CertificateFile, filepath.Join(filepath.Dir(p.Path), "certificate.pem")}, {p.Settings.CertificateKey, filepath.Join(filepath.Dir(p.Path), "certificate.key")}}
		p.Config.Certificate.File = "certificate.pem"
		p.Config.Certificate.Key = "certificate.key"
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
	if journal.Phase == "ready" {
		return nil
	}
	if journal.Phase == "prepared" {
		if err = store.Close(); err != nil {
			return err
		}
		locked = false
		return w.finish(ctx, p, journal)
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
	for _, file := range copies {
		if err = file.save(); err != nil {
			return err
		}
	}
	if p.Settings.NeedsCloudflare() {
		if err = state.Write(p.Settings.TokenFile, []byte(p.token+"\n")); err != nil {
			return err
		}
	}
	if err = state.Write(p.Path, b); err != nil {
		return err
	}

	if p.importCertificate != "" {
		if err = certificate.Import(daemon.CertificateOptions(p.Settings, p.StateDir), p.importCertificate, p.importKey); err != nil {
			return err
		}
	}
	if _, err = store.LoadOrCreateIdentity(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if p.Service {
		install := w.install
		if len(p.identity) > 0 {
			install = w.stage
		}
		if err = install(ctx, p.Path, p.Settings); err != nil {
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
	return w.finish(ctx, p, journal)
}

func (w *Workflow) finish(ctx context.Context, p plan, journal state.Deployment) error {
	if !p.Service || !p.Start {
		return nil
	}
	if err := w.start(ctx); err != nil {
		return err
	}
	if err := w.wait(ctx, p.StateDir, p.Settings); err != nil {
		return err
	}
	journal.Phase = "ready"
	if err := state.SaveDeployment(p.StateDir, journal); err != nil {
		return err
	}
	if p.Service {
		return w.ownState(filepath.Join(p.StateDir, "setup.json"))
	}
	return nil
}

// resumePrepared finishes an already approved installation without repeating
// discovery, credentials, identity creation or DNS adoption.
func (w *Workflow) resumePrepared(ctx context.Context, path, dir string) error {
	if path != w.paths.config || dir != w.paths.state {
		return errors.New("恢复系统服务需要标准配置和状态目录")
	}
	installation, err := state.AcquireInstallation(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer installation.Close()
	journal, err := state.ReadDeployment(dir)
	if err != nil {
		return err
	}
	if journal.Phase != "prepared" {
		return errors.New("安装阶段不是 prepared")
	}
	raw, err := fileio.ReadRegularFile(path, 1<<20)
	if err != nil {
		return err
	}
	c, err := config.Decode(raw)
	if err != nil {
		return err
	}
	canonical, err := ConfigBytes(c)
	if err != nil {
		return err
	}
	if Hash(canonical) != journal.ConfigHash {
		return errors.New("配置与已批准的安装不一致，请使用 config check 和 service start")
	}
	settings, err := Resolve(c, path)
	if err != nil {
		return err
	}
	if err = daemon.Check(settings); err != nil {
		return err
	}
	if err = w.refresh(ctx, settings); err != nil {
		return err
	}
	return w.finish(ctx, plan{Path: path, StateDir: dir, Settings: settings, Service: true, Start: true}, journal)
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
				if s.RelayEnabled && s.Access == config.Tailnet && status.Tailnet.State == "degraded" {
					return fmt.Errorf("中继已运行，但 Tailnet 检查失败：%s", status.Tailnet.Detail)
				}
				if (!s.PublishDNS || status.DNS.State == "ready") && (!s.RelayEnabled || s.Access != config.Tailnet || status.Tailnet.State == "ready") {
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

type certificateCopy struct{ source, target string }

func (c certificateCopy) save() error {
	b, err := fileio.ReadRegularFile(c.source, 1<<20)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(c.target); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("手动证书目标必须是普通文件")
		}
		previous, err := fileio.ReadRegularFile(c.target, 1<<20)
		if err != nil {
			return err
		}
		if !bytes.Equal(b, previous) {
			return errors.New("已有手动证书与本次来源不同，拒绝覆盖")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return state.WriteFile(c.target, b, 0600, true)
}

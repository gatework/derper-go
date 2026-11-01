package setup

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/dns"
	"github.com/gatework/derper-go/internal/state"
)

// Initialize owns inspection, input requirements, preview, consent and execution.
// Request and Interaction are invocation-local and must not be used concurrently.
func (w *Workflow) Initialize(ctx context.Context, r Request, ui Interaction) (Result, error) {
	var result Result
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if ui == nil {
		return result, errors.New("初始化需要交互适配器")
	}
	if r.Mode > PrepareForeground {
		return result, errors.New("初始化部署模式无效")
	}
	if r.ConfigPath == "" {
		r.ConfigPath = w.paths.config
		if r.Mode == PrepareForeground {
			r.ConfigPath = "config.json"
		}
	}
	path, err := filepath.Abs(r.ConfigPath)
	if err != nil {
		return result, err
	}
	dir := r.StateDir
	if dir == "" {
		dir = DataDir(path)
		if path == w.paths.config {
			dir = w.paths.state
		}
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return result, err
	}
	result.ConfigPath, result.StateDir = path, dir
	c, err := config.Load(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	configMissing := errors.Is(err, os.ErrNotExist)
	journal, journalErr := state.ReadDeployment(dir)
	if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) {
		return result, journalErr
	}
	if journalErr == nil {
		if configMissing {
			c, err = config.Decode(journal.Config)
			if err != nil {
				return result, err
			}
		}
		if journal.Phase == "ready" || journal.Phase == "prepared" {
			if err = assertExisting(c, path, dir, r); err != nil {
				return result, err
			}
			if r.Preview {
				result.Outcome, result.Phase = PreviewedDeployment, journal.Phase
				return result, nil
			}
			if journal.Phase == "prepared" && r.Mode == StartService {
				ui.Show(Display{Kind: ResumingInstallation})
				if err = w.resumePrepared(ctx, path, dir); err != nil {
					return result, err
				}
			}
			return result, nil
		}
		inUse, err := state.InUse(dir)
		if err != nil {
			return result, err
		}
		if inUse {
			result.Outcome = RunningDeployment
			return result, nil
		}
		ui.Show(Display{Kind: ContinuingInstallation})
	}
	c, err = r.Overrides.apply(c)
	if err != nil {
		return result, err
	}
	if r.Mode != PrepareForeground {
		if err = w.checkHost(); err != nil {
			return result, err
		}
	}
	for _, field := range []struct {
		need  Need
		value *string
	}{{Domain, &c.Domain}, {Email, &c.Email}} {
		if field.need == Email && c.Certificate.File != "" {
			continue
		}
		if *field.value != "" {
			continue
		}
		if !r.Interactive {
			return result, fmt.Errorf("缺少%s；非交互模式请通过命令选项提供", field.need)
		}
		*field.value, err = ui.Read(ctx, field.need)
		if err != nil {
			return result, err
		}
		if *field.value == "" {
			return result, fmt.Errorf("%s不能为空", field.need)
		}
	}
	c.Domain = strings.ToLower(strings.TrimSuffix(c.Domain, "."))
	settings, err := Resolve(c, path)
	if err != nil {
		return result, err
	}
	if !r.Preview && !r.Interactive && (!r.Consent.Install || settings.AutomaticCertificate() && !r.Consent.Terms) {
		return result, errors.New("非交互初始化需要 --yes；自动签发还需要单独提供 --accept-terms")
	}
	token := ""
	if settings.NeedsCloudflare() {
		source := r.Sources.TokenFile
		if source == "" && c.Cloudflare.TokenFile != "" {
			source = settings.TokenFile
		}
		if source == "" {
			if _, e := os.Stat(settings.TokenFile); e == nil {
				source = settings.TokenFile
			}
		}
		switch {
		case source != "" || os.Getenv("CLOUDFLARE_API_TOKEN") != "":
			token, err = (cloudflare.Credentials{File: source}).Read()
		case r.Interactive:
			token, err = ui.Read(ctx, CloudflareToken)
		default:
			err = errors.New("缺少 Cloudflare 凭据，请指定 --token-file 或 CLOUDFLARE_API_TOKEN")
		}
		if err != nil {
			return result, err
		}
	}
	p, err := w.prepare(ctx, preparation{
		Config: c, Path: path, StateDir: dir, Token: token,
		Service: r.Mode != PrepareForeground, Start: r.Mode == StartService,
		IdentityPath: r.Sources.Identity, ImportCertificate: r.Sources.ImportCertificate, ImportKey: r.Sources.ImportKey,
	})
	if err != nil {
		return result, err
	}
	ui.Show(Display{Kind: InstallationSummary, Summary: installationSummary(p)})
	if r.Preview {
		result.Outcome = PreviewedInstallation
		return result, nil
	}
	consent := r.Consent
	if !consent.Install {
		consent, err = ui.Confirm(ctx, Confirmation{TermsRequired: p.Settings.AutomaticCertificate()})
		if err != nil {
			return result, err
		}
		if !consent.Install {
			return result, errors.New("操作已取消")
		}
	} else if p.Settings.AutomaticCertificate() && !consent.Terms {
		return result, errors.New("--yes 不代表接受证书机构条款；请提供 --accept-terms")
	}
	if err = w.apply(ctx, p, consent.Terms); err != nil {
		return result, fmt.Errorf("初始化未完成：%w；已保存的身份与证书会在重试时保留", err)
	}
	switch {
	case r.Mode == PrepareForeground:
		result.Outcome = ForegroundPrepared
	case r.Mode == PrepareService && r.Sources.Identity != "":
		result.Outcome = MigrationStaged
	case r.Mode == PrepareService:
		result.Outcome = ServicePrepared
	case !p.Settings.RelayEnabled:
		result.Outcome = BootstrapReady
	default:
		result.Outcome = RelayReady
	}
	return result, nil
}

func installationSummary(p plan) Summary {
	s := p.Settings
	summary := Summary{
		Domain: s.Domain, HTTPSAddress: s.HTTPSAddress(), ConfigPath: p.Path, StateDir: p.StateDir,
		Admission: s.Access, Region: s.Region, ControllerFailOpen: s.AdmissionFailOpen,
		MeshConfigured: s.MeshKeyFile != "", MeshPeers: len(s.MeshPeers),
		ExistingListener: p.ExistingListener, AlternatePort: p.AlternatePort,
		Service: p.Service, Start: p.Start,
		AutomaticCertificate: s.AutomaticCertificate(), CA: s.CA, TermsURL: p.TermsURL,
	}
	if s.RelayEnabled && s.UsesController() {
		endpoint, _ := url.Parse(s.AdmissionURL)
		endpoint.RawQuery = ""
		summary.ControllerURL = endpoint.String()
	}
	summary.Changes = make([]dns.Change, len(p.Changes))
	copy(summary.Changes, p.Changes)
	for i, ch := range summary.Changes {
		if ch.Before != nil {
			before := *ch.Before
			summary.Changes[i].Before = &before
		}
	}
	return summary
}

func assertExisting(c config.Config, path, dir string, r Request) error {
	candidate, err := r.Overrides.apply(c)
	if err != nil {
		return err
	}
	current, err := Resolve(c, path)
	if err != nil {
		return err
	}
	requested, err := Resolve(candidate, path)
	if err != nil {
		return err
	}
	requested, err = checkExistingInputs(current, requested, dir, existingInputs{
		tokenFile: r.Sources.TokenFile, identity: r.Sources.Identity,
		importCertificate: r.Sources.ImportCertificate, importKey: r.Sources.ImportKey,
		manualCertificate: r.Overrides.CertificateFile != nil, manualKey: r.Overrides.CertificateKey != nil,
	})
	if err != nil {
		return err
	}
	if changed := config.ChangedFields(current, requested); len(changed) > 0 {
		return fmt.Errorf("已有部署设置不同：%s；请修改配置后使用 reload 或 restart", strings.Join(changed, ", "))
	}
	return nil
}

package setup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/dns"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
)

type scriptedInteraction struct {
	t             *testing.T
	displays      []Display
	reads         []Need
	confirmations int
	read          func(Need) (string, error)
	show          func(Display)
	confirm       func(Confirmation) (Consent, error)
}

func TestInitializeAutomationConsentPrecedesCredentialsAndDiscovery(t *testing.T) {
	for _, consent := range []Consent{{}, {Install: true}, {Terms: true}} {
		w, r := fixture(t)
		r.Consent = consent
		r.Sources.TokenFile = filepath.Join(t.TempDir(), "absent.token")
		w.checkTailnet = func(context.Context, string, int) (int, error) {
			t.Fatal("discovery before automation approval")
			return 0, nil
		}
		ui := &scriptedInteraction{t: t}
		if _, err := w.Initialize(t.Context(), r, ui); err == nil || !strings.Contains(err.Error(), "非交互初始化需要 --yes") {
			t.Fatal("approval did not precede credential acquisition", consent, err)
		}
		if len(ui.displays) != 0 {
			t.Fatal("prepared unapproved automation", ui.displays)
		}
		if _, err := os.Stat(filepath.Dir(r.ConfigPath)); !os.IsNotExist(err) {
			t.Fatal("wrote before approval", err)
		}
	}
}

func TestInitializeInteractiveInputAndDetachedApprovalSummary(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	w, r := fixture(t)
	r.Overrides = Overrides{}
	r.Sources = Sources{}
	r.Consent = Consent{}
	r.Interactive = true
	mode, endpoint := config.Controller, "https://admit.example/check?token=fixture-secret"
	r.Overrides.Admission, r.Overrides.AdmissionURL = &mode, &endpoint
	var events []string
	ui := &scriptedInteraction{t: t,
		read: func(n Need) (string, error) {
			switch n {
			case Domain:
				events = append(events, "domain")
				return "Relay.Example.Com.", nil
			case Email:
				events = append(events, "email")
				return "ops@example.com", nil
			case CloudflareToken:
				events = append(events, "token")
				return "fixture-input-token", nil
			default:
				t.Fatalf("unexpected need: %v", n)
				return "", nil
			}
		},
		show: func(d Display) {
			events = append(events, "summary")
			if d.Kind != InstallationSummary || d.Summary.Domain != "relay.example.com" || d.Summary.TermsURL != "https://ca.example/terms" {
				t.Fatal("incomplete summary", d)
			}
			if d.Summary.ControllerURL != "https://admit.example/check" {
				t.Fatal("controller query exposed in summary")
			}
			// Display data cannot change the executable approval snapshot.
			d.Summary.Changes[0].Before.Content = "192.0.2.99"
			d.Summary.Changes[0].Action = "create"
		},
		confirm: func(scope Confirmation) (Consent, error) {
			events = append(events, "confirm")
			if !scope.TermsRequired {
				t.Fatal("automatic certificate terms omitted")
			}
			return Consent{Install: true, Terms: true}, nil
		},
	}
	if _, err := w.Initialize(t.Context(), r, ui); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"domain", "email", "token", "summary", "confirm"}) {
		t.Fatal("input or confirmation order changed", events)
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || len(journal.ApprovedDNS) != 1 || journal.ApprovedDNS[0].Content != "192.0.2.2" || journal.AcceptedCA != config.ProductionCA {
		t.Fatal("display mutation changed approval", journal, err)
	}
}

func TestInitializeInputFailureAndDeclineDoNotWrite(t *testing.T) {
	for _, inputErr := range []error{io.EOF, context.Canceled} {
		w, r := fixture(t)
		r.Interactive = true
		r.Overrides.Domain = nil
		ui := &scriptedInteraction{t: t, read: func(Need) (string, error) { return "", inputErr }}
		if _, err := w.Initialize(t.Context(), r, ui); !errors.Is(err, inputErr) {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Dir(r.ConfigPath)); !os.IsNotExist(err) {
			t.Fatal("failed input wrote deployment", err)
		}
	}
	w, r := fixture(t)
	r.Interactive, r.Consent = true, Consent{}
	ui := &scriptedInteraction{t: t, confirm: func(Confirmation) (Consent, error) { return Consent{}, nil }}
	if _, err := w.Initialize(t.Context(), r, ui); err == nil || !strings.Contains(err.Error(), "操作已取消") {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(r.ConfigPath)); !os.IsNotExist(err) {
		t.Fatal("declined installation wrote deployment", err)
	}
}

func (s *scriptedInteraction) Read(_ context.Context, n Need) (string, error) {
	s.t.Helper()
	s.reads = append(s.reads, n)
	if s.read == nil {
		s.t.Fatalf("unexpected input request: %v", n)
	}
	return s.read(n)
}
func (s *scriptedInteraction) Show(d Display) {
	s.displays = append(s.displays, d)
	if s.show != nil {
		s.show(d)
	}
}
func (s *scriptedInteraction) Confirm(_ context.Context, c Confirmation) (Consent, error) {
	s.t.Helper()
	s.confirmations++
	if s.confirm == nil {
		s.t.Fatal("unexpected confirmation")
	}
	return s.confirm(c)
}
func TestInitializePreviewReadsAndReviewsWithoutWriting(t *testing.T) {
	root := t.TempDir()
	cert := testutil.Cert(t, "relay.example.com", 1)
	certPath, keyPath := filepath.Join(root, "source.pem"), filepath.Join(root, "source.key")
	if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	domain, listen, mode, no := "relay.example.com", "127.0.0.1:8443", config.Public, false
	path := filepath.Join(root, "deployment", "config.json")
	request := Request{ConfigPath: path, Mode: PrepareForeground, Preview: true, Overrides: Overrides{Domain: &domain, Listen: &listen, Admission: &mode, PublishDNS: &no, STUNEnabled: &no, CertificateFile: &certPath, CertificateKey: &keyPath}}
	workflow := New()
	workflow.portAvailable = func(context.Context, string, int) bool { return true }
	interaction := &scriptedInteraction{t: t}
	result, err := workflow.Initialize(t.Context(), request, interaction)
	if err != nil || result.Outcome != PreviewedInstallation {
		t.Fatal(result, err)
	}
	if len(interaction.displays) != 1 || interaction.displays[0].Kind != InstallationSummary || interaction.confirmations != 0 {
		t.Fatal(interaction.displays, interaction.confirmations)
	}
	if interaction.displays[0].Summary.Domain != domain {
		t.Fatal("summary lost selected domain")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("preview wrote deployment", err)
	}
}

func manualInitialization(t *testing.T) (*Workflow, Request) {
	t.Helper()
	root := t.TempDir()
	cert := testutil.Cert(t, "relay.example.com", 1)
	certPath, keyPath := filepath.Join(root, "source.pem"), filepath.Join(root, "source.key")
	for path, data := range map[string][]byte{certPath: cert.CertPEM, keyPath: cert.KeyPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	domain, listen, mode, no := "relay.example.com", "127.0.0.1:8443", config.Public, false
	request := Request{ConfigPath: filepath.Join(root, "deployment", "config.json"), Mode: PrepareForeground, Consent: Consent{Install: true}, Overrides: Overrides{Domain: &domain, Listen: &listen, Admission: &mode, PublishDNS: &no, STUNEnabled: &no, CertificateFile: &certPath, CertificateKey: &keyPath}}
	workflow := New()
	workflow.portAvailable = func(context.Context, string, int) bool { return true }
	return workflow, request
}
func TestInitializeExistingPreviewSkipsPreparationAndOmittedSources(t *testing.T) {
	w, r := manualInitialization(t)
	first, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(first.StateDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	w.checkHost = func() error { t.Fatal("existing preview checked host"); return nil }
	w.portAvailable = func(context.Context, string, int) bool { t.Fatal("existing preview repeated discovery"); return false }
	interaction := &scriptedInteraction{t: t}
	result, err := w.Initialize(t.Context(), Request{ConfigPath: r.ConfigPath, Preview: true}, interaction)
	if err != nil || result.Outcome != PreviewedDeployment || result.Phase != "prepared" {
		t.Fatal(result, err)
	}
	if len(interaction.reads) != 0 || len(interaction.displays) != 0 || interaction.confirmations != 0 {
		t.Fatal(interaction)
	}
	after, err := os.ReadFile(filepath.Join(result.StateDir, "identity.json"))
	if err != nil || string(after) != string(before) {
		t.Fatal("identity changed", err)
	}
}

func TestInitializePreparedRecoveryStartsWithoutDiscoveryOrReinstall(t *testing.T) {
	w, r := manualInitialization(t)
	r.Mode = PrepareService
	w.paths = deploymentPaths{config: r.ConfigPath, state: filepath.Join(filepath.Dir(r.ConfigPath), "state")}
	w.checkHost = func() error { return nil }
	w.install = func(context.Context, string, config.Settings) error { return nil }
	w.ownState = func(string) error { return nil }
	first, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.ReadFile(filepath.Join(first.StateDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	w.install = func(context.Context, string, config.Settings) error {
		t.Fatal("reinstalled prepared deployment")
		return nil
	}
	w.portAvailable = func(context.Context, string, int) bool { t.Fatal("repeated discovery"); return false }
	refreshed, started := false, false
	w.refresh = func(context.Context, config.Settings) error { refreshed = true; return nil }
	w.start = func(context.Context) error {
		lock, err := state.Open(first.StateDir)
		if err != nil {
			t.Fatal("writer lock held during start", err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		started = true
		return nil
	}
	w.wait = func(context.Context, string, config.Settings) error { return nil }
	ui := &scriptedInteraction{t: t}
	result, err := w.Initialize(t.Context(), Request{ConfigPath: r.ConfigPath}, ui)
	if err != nil || result.Outcome != ExistingDeployment || !refreshed || !started {
		t.Fatal(result, err, refreshed, started)
	}
	if len(ui.reads) != 0 || ui.confirmations != 0 || len(ui.displays) != 1 || ui.displays[0].Kind != ResumingInstallation {
		t.Fatal(ui)
	}
	after, err := os.ReadFile(filepath.Join(first.StateDir, "identity.json"))
	if err != nil || string(after) != string(identity) {
		t.Fatal("identity changed", err)
	}
	journal, err := state.ReadDeployment(first.StateDir)
	if err != nil || journal.Phase != "ready" {
		t.Fatal(journal, err)
	}
}

func TestInitializeCredentialSourcePrecedence(t *testing.T) {
	for _, source := range []string{"explicit", "configured", "managed", "environment", "prompt"} {
		t.Run(source, func(t *testing.T) {
			w, r := fixture(t)
			r.Preview, r.Interactive = true, true
			configured := filepath.Join(t.TempDir(), "configured.token")
			managed := filepath.Join(filepath.Dir(r.ConfigPath), "cloudflare.token")
			if err := os.MkdirAll(filepath.Dir(r.ConfigPath), 0700); err != nil {
				t.Fatal(err)
			}
			for path, token := range map[string]string{configured: "configured-token", managed: "managed-token"} {
				if err := state.Write(path, []byte(token)); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("CLOUDFLARE_API_TOKEN", "environment-token")
			c := config.Config{Domain: "relay.example.com", Email: "ops@example.com", Cloudflare: config.Cloudflare{TokenFile: configured}}
			expected := "secret-test-token"
			if source != "explicit" {
				r.Sources.TokenFile = ""
				expected = "configured-token"
			}
			if source != "explicit" && source != "configured" {
				c.Cloudflare.TokenFile = ""
				expected = "managed-token"
			}
			if source == "environment" || source == "prompt" {
				if err := os.Remove(managed); err != nil {
					t.Fatal(err)
				}
				expected = "environment-token"
			}
			if source == "prompt" {
				t.Setenv("CLOUDFLARE_API_TOKEN", "")
				expected = "prompt-token"
			}
			raw, err := ConfigBytes(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Write(r.ConfigPath, raw); err != nil {
				t.Fatal(err)
			}
			w.dnsPlan = func(_ context.Context, _ config.Settings, _, token string) ([]dns.Change, error) {
				if token != expected {
					t.Fatal("credential precedence changed")
				}
				return nil, nil
			}
			ui := &scriptedInteraction{t: t, read: func(n Need) (string, error) {
				if n != CloudflareToken || source != "prompt" {
					t.Fatal("unexpected credential prompt", n)
				}
				return "prompt-token", nil
			}}
			if _, err := w.Initialize(t.Context(), r, ui); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInitializeOmittedOverridesPreserveIntentAndExplicitZeroReplacesIt(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		w, r := fixture(t)
		c := config.Config{Domain: "relay.example.com", Email: "ops@example.com", Region: 950, LogLevel: "warn"}
		c.Relay.Homepage = "blank"
		httpPort, enabled := 8080, true
		c.HTTP.Port, c.DNS.Publish, c.STUN.Enabled = &httpPort, &enabled, &enabled
		raw, err := ConfigBytes(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(r.ConfigPath), 0700); err != nil {
			t.Fatal(err)
		}
		if err := state.Write(r.ConfigPath, raw); err != nil {
			t.Fatal(err)
		}
		w.checkTailnet = func(context.Context, string, int) (int, error) { return 900, nil }
		expectedRegion := 950
		if explicit {
			zero, off, disabled := 0, false, -1
			r.Overrides.Region, r.Overrides.PublishDNS, r.Overrides.STUNEnabled, r.Overrides.HTTPPort = &zero, &off, &off, &disabled
			expectedRegion = 0
		}
		if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err != nil {
			t.Fatal(err)
		}
		loaded, err := config.Load(r.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Region != expectedRegion || loaded.LogLevel != "warn" || loaded.Relay.Homepage != "blank" || *loaded.DNS.Publish == explicit || *loaded.STUN.Enabled == explicit {
			t.Fatal("override lost omitted settings or explicit values", explicit, loaded)
		}
		if explicit && *loaded.HTTP.Port != -1 || !explicit && *loaded.HTTP.Port != 8080 {
			t.Fatal("HTTP override lost", explicit, loaded.HTTP)
		}
	}
}

func TestInitializeRunningUnfinishedDeploymentOnlyReturnsStatus(t *testing.T) {
	w, r := fixture(t)
	store, err := state.Open(r.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw := []byte(`{"domain":"relay.example.com","email":"ops@example.com"}`)
	if err := state.SaveDeployment(r.StateDir, state.Deployment{Config: raw, ConfigHash: Hash(raw), Phase: "approved"}); err != nil {
		t.Fatal(err)
	}
	invalidDomain := "not a domain"
	r.Overrides.Domain = &invalidDomain
	r.Sources.TokenFile = filepath.Join(t.TempDir(), "absent.token")
	ui := &scriptedInteraction{t: t}
	result, err := w.Initialize(t.Context(), r, ui)
	if err != nil || result.Outcome != RunningDeployment || len(ui.displays) != 0 {
		t.Fatal(result, err, ui.displays)
	}
	if _, err := os.Stat(r.ConfigPath); !os.IsNotExist(err) {
		t.Fatal("running deployment was changed", err)
	}
}

func TestInitializePreparedRecoveryRechecksApprovedConfig(t *testing.T) {
	w, r := fixture(t)
	r.Mode = PrepareService
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(r.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded.LogLevel = "debug"
	raw, err := ConfigBytes(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Write(r.ConfigPath, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Initialize(t.Context(), Request{ConfigPath: r.ConfigPath}, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "配置与已批准的安装不一致") {
		t.Fatal(err)
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || journal.Phase != "prepared" {
		t.Fatal(journal, err)
	}
}

func TestInitializeDefaultPathsFollowDeploymentMode(t *testing.T) {
	t.Chdir(t.TempDir())
	w, r := manualInitialization(t)
	r.ConfigPath = ""
	result, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t})
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if result.ConfigPath != filepath.Join(cwd, "config.json") || result.StateDir != filepath.Join(cwd, "state") {
		t.Fatal("foreground defaults changed", result)
	}
	w, r = fixture(t)
	r.ConfigPath, r.StateDir, r.Mode = "", "", PrepareService
	result, err = w.Initialize(t.Context(), r, &scriptedInteraction{t: t})
	if err != nil || result.ConfigPath != w.paths.config || result.StateDir != w.paths.state {
		t.Fatal("service defaults changed", result, err)
	}
}

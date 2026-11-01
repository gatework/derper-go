package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/dns"
	"github.com/gatework/derper-go/internal/state"
)

func fixture(t *testing.T) (*Workflow, Request) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "new-deployment")
	token := filepath.Join(root, "source.token")
	if err := os.WriteFile(token, []byte("secret-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	w := New()
	w.paths = deploymentPaths{config: filepath.Join(dir, "config.json"), state: filepath.Join(dir, "state")}
	w.checkHost = func() error { return nil }
	w.portAvailable = func(context.Context, string, int) bool { return true }
	w.stunAvailable = func(context.Context, string, int) bool { return true }
	w.checkTailnet = func(context.Context, string, int) (int, error) { return 907, nil }
	w.discoverIPv4 = func(context.Context) (string, error) { return "192.0.2.1", nil }
	w.dnsPlan = func(context.Context, config.Settings, string, string) ([]dns.Change, error) {
		r := cloudflare.Record{ID: "existing", Type: "A", Name: "relay.example.com", Content: "192.0.2.2", TTL: 1}
		return []dns.Change{{Action: "adopt", Before: &r, After: cloudflare.Record{Type: "A", Name: r.Name, Content: "192.0.2.1", TTL: 1}}}, nil
	}
	w.terms = func(context.Context, string) (string, error) { return "https://ca.example/terms", nil }
	w.install = func(context.Context, string, config.Settings) error { return nil }
	w.stage = func(context.Context, string, config.Settings) error { return nil }
	w.ownState = func(string) error { return nil }
	w.start = func(context.Context) error { t.Fatal("unexpected service start"); return nil }
	w.wait = func(context.Context, string, config.Settings) error { t.Fatal("unexpected readiness wait"); return nil }
	w.refresh = func(context.Context, config.Settings) error { t.Fatal("unexpected service refresh"); return nil }
	domain, email := "relay.example.com", "ops@example.com"
	return w, Request{ConfigPath: w.paths.config, StateDir: w.paths.state, Mode: PrepareForeground,
		Overrides: Overrides{Domain: &domain, Email: &email}, Sources: Sources{TokenFile: token}, Consent: Consent{Install: true, Terms: true}}
}

func TestInitializePreviewAndApprovalPersistOnlyChoices(t *testing.T) {
	w, r := fixture(t)
	w.portAvailable = func(_ context.Context, _ string, port int) bool { return port == 8443 }
	r.Preview = true
	ui := &scriptedInteraction{t: t}
	if result, err := w.Initialize(t.Context(), r, ui); err != nil || result.Outcome != PreviewedInstallation {
		t.Fatal(result, err)
	}
	summary := ui.displays[0].Summary
	if summary.HTTPSAddress != ":8443" || summary.Region != 907 || !summary.AlternatePort {
		t.Fatal("lost discovery decisions", summary)
	}
	if _, err := os.Stat(filepath.Dir(r.ConfigPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview wrote disk", err)
	}
	r.Preview = false
	r.Interactive = true
	r.Consent.Terms = false
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "--yes 不代表") {
		t.Fatal("terms implicitly accepted", err)
	}
	if _, err := os.Stat(filepath.Dir(r.ConfigPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unaccepted installation wrote disk", err)
	}
	r.Consent.Terms = true
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-test-token", "accepted_ca", "state_dir", "192.0.2.1"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("runtime state leaked into config", string(b))
		}
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != "prepared" || journal.AcceptedCA != config.ProductionCA || len(journal.ApprovedDNS) != 1 {
		t.Fatalf("incomplete journal: %+v", journal)
	}
	info, err := os.Stat(filepath.Join(filepath.Dir(r.ConfigPath), "cloudflare.token"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential permissions", err)
	}
}

func TestInitializeRetriesApprovedInstallationAndReleasesWriterLockBeforeStart(t *testing.T) {
	w, r := fixture(t)
	r.Mode = StartService
	attempts, discoveries := 0, 0
	w.dnsPlan = func(context.Context, config.Settings, string, string) ([]dns.Change, error) {
		discoveries++
		return nil, nil
	}
	w.install = func(context.Context, string, config.Settings) error {
		attempts++
		if attempts == 1 {
			return errors.New("injected install failure")
		}
		return nil
	}
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err == nil {
		t.Fatal("failure ignored")
	}
	identity, err := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || journal.Phase != "approved" {
		t.Fatal("lost resume point", err)
	}
	started := false
	w.start = func(context.Context) error {
		lock, err := state.Open(r.StateDir)
		if err != nil {
			return err
		}
		if err = lock.Close(); err != nil {
			return err
		}
		// The installation lock must remain held through startup.
		if lock, err := state.AcquireInstallation(filepath.Dir(r.ConfigPath)); err == nil {
			lock.Close()
			t.Fatal("installation lock released before start")
		}
		started = true
		return nil
	}
	w.wait = func(context.Context, string, config.Settings) error { return nil }
	result, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t})
	if err != nil || result.Outcome != RelayReady {
		t.Fatal(result, err)
	}
	current, err := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if err != nil || !bytes.Equal(identity, current) || !started || attempts != 2 || discoveries != 2 {
		t.Fatal("retry changed identity or skipped preparation", err, started, attempts, discoveries)
	}
}

func TestInitializeRejectsConfigChangedAfterSummary(t *testing.T) {
	w, r := fixture(t)
	sentinel := []byte("operator edit")
	ui := &scriptedInteraction{t: t, show: func(d Display) {
		if d.Kind != InstallationSummary {
			return
		}
		if err := os.MkdirAll(filepath.Dir(r.ConfigPath), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.ConfigPath, sentinel, 0600); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := w.Initialize(t.Context(), r, ui); err == nil || !strings.Contains(err.Error(), "配置在确认后已发生变化") {
		t.Fatal("overwrote concurrent edit", err)
	}
	b, err := os.ReadFile(r.ConfigPath)
	if err != nil || !bytes.Equal(b, sentinel) {
		t.Fatal("operator edit lost", err)
	}
}

func TestInitializeWriteFailurePreservesRecoveryJournal(t *testing.T) {
	w, r := fixture(t)
	ui := &scriptedInteraction{t: t, show: func(d Display) {
		if d.Kind != InstallationSummary {
			return
		}
		// A directory at the managed token path simulates a durable write failure.
		if err := os.MkdirAll(filepath.Join(filepath.Dir(r.ConfigPath), "cloudflare.token"), 0700); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := w.Initialize(t.Context(), r, ui); err == nil {
		t.Fatal("token write failure ignored")
	}
	if _, err := os.Stat(r.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published config without credentials", err)
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || journal.Phase != "approved" {
		t.Fatal("missing recovery journal", err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(r.ConfigPath), "cloudflare.token")); err != nil {
		t.Fatal(err)
	}
	// Config is still absent: retry must recover its choices from the journal.
	if _, err := w.Initialize(t.Context(), Request{ConfigPath: r.ConfigPath, Mode: PrepareForeground, Sources: r.Sources, Consent: r.Consent}, &scriptedInteraction{t: t}); err != nil {
		t.Fatal("failed to recover journal configuration", err)
	}
}

func TestInitializeCancellationAndSymlinkRefusal(t *testing.T) {
	w, r := fixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := w.Initialize(ctx, r, &scriptedInteraction{t: t}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	ui := &scriptedInteraction{t: t, show: func(Display) { cancel() }}
	if _, err := w.Initialize(ctx, r, ui); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(r.ConfigPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled initialization wrote disk", err)
	}
	target := t.TempDir()
	ui = &scriptedInteraction{t: t, show: func(Display) {
		if err := os.Symlink(target, filepath.Dir(r.ConfigPath)); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := w.Initialize(t.Context(), r, ui); err == nil {
		t.Fatal("followed installation symlink")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside deployment", err)
	}
}

func TestInitializePreflightChecksEnabledListenersBeforeWriting(t *testing.T) {
	w, r := fixture(t)
	w.stunAvailable = func(context.Context, string, int) bool { return false }
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err == nil {
		t.Fatal("occupied STUN accepted")
	}
	off, httpPort := false, 80
	r.Overrides.STUNEnabled, r.Overrides.HTTPPort = &off, &httpPort
	w.portAvailable = func(_ context.Context, _ string, port int) bool { return port != 80 }
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err == nil {
		t.Fatal("occupied HTTP accepted")
	}
	if _, err := os.Stat(filepath.Dir(r.ConfigPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight wrote files", err)
	}
}

func TestInitializePreparedRetrySkipsReinstallAndCredentialReads(t *testing.T) {
	w, r := fixture(t)
	r.Mode = StartService
	calls := 0
	w.install = func(context.Context, string, config.Settings) error { calls++; return nil }
	w.start = func(context.Context) error { return errors.New("injected start failure") }
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err == nil {
		t.Fatal("start failure ignored")
	}
	before, err := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(r.ConfigPath), "cloudflare.token")); err != nil {
		t.Fatal(err)
	}
	w.discoverIPv4 = func(context.Context) (string, error) { t.Fatal("rediscovered address"); return "", nil }
	w.refresh = func(context.Context, config.Settings) error { return nil }
	w.start = func(context.Context) error {
		lock, err := state.Open(r.StateDir)
		if err != nil {
			return err
		}
		return lock.Close()
	}
	w.wait = func(context.Context, string, config.Settings) error { return nil }
	if _, err := w.Initialize(t.Context(), Request{ConfigPath: r.ConfigPath}, &scriptedInteraction{t: t}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || journal.Phase != "ready" || calls != 1 || !bytes.Equal(before, after) {
		t.Fatal("resume recreated installation", journal.Phase, calls, err)
	}
}

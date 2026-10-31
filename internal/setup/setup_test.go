package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/dns"
	"github.com/gatework/derper-go/internal/state"
)

func fixture(t *testing.T) (*Workflow, Request) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "new-deployment")
	w := New()
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
	w.ownState = func(string) error { return nil }
	return w, Request{Config: config.Config{Domain: "relay.example.com", Email: "ops@example.com"}, Path: filepath.Join(dir, "config.json"), StateDir: filepath.Join(dir, "state"), Token: "secret-test-token"}
}
func TestPlanIsReadOnlyAndPersistsOnlyChoices(t *testing.T) {
	w, r := fixture(t)
	w.portAvailable = func(_ context.Context, _ string, port int) bool { return port == 8443 }
	p, err := w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.Relay.Listen != ":8443" || p.Config.Region != 907 || !p.AlternatePort {
		t.Fatal("lost discovery decisions")
	}
	if _, err = os.Stat(filepath.Dir(r.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("prepare wrote disk")
	}
	if err = w.Apply(context.Background(), p, false); err == nil {
		t.Fatal("terms implicitly accepted")
	}
	if _, err = os.Stat(filepath.Dir(r.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unaccepted plan wrote disk")
	}
	if err = w.Apply(context.Background(), p, true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.Path)
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
	info, err := os.Stat(filepath.Join(filepath.Dir(r.Path), "cloudflare.token"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential permissions", err)
	}
}
func TestResumeAfterInstallFailureAndReleaseLockBeforeStart(t *testing.T) {
	w, r := fixture(t)
	p, err := w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	p.Service = true
	p.Start = true
	attempts := 0
	w.install = func(context.Context, string, config.Settings) error {
		attempts++
		if attempts == 1 {
			return errors.New("injected install failure")
		}
		return nil
	}
	if err = w.Apply(context.Background(), p, true); err == nil {
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
	r.Config, err = config.Load(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	p, err = w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	p.Service = true
	p.Start = true
	started := false
	w.start = func(context.Context) error {
		lock, e := state.Open(r.StateDir)
		if e != nil {
			return e
		}
		lock.Close()
		started = true
		return nil
	}
	w.wait = func(context.Context, string, config.Settings) error { return nil }
	if err = w.Apply(context.Background(), p, true); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if !bytes.Equal(identity, current) || !started {
		t.Fatal("identity changed or start missing")
	}
}
func TestChangedConfigAndWriteFailurePreserveExistingFiles(t *testing.T) {
	w, r := fixture(t)
	p, err := w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(r.Path), 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := []byte("operator edit")
	if err = os.WriteFile(r.Path, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err = w.Apply(context.Background(), p, true); err == nil {
		t.Fatal("overwrote concurrent edit")
	}
	b, _ := os.ReadFile(r.Path)
	if !bytes.Equal(b, sentinel) {
		t.Fatal("operator edit lost")
	}
	if err = os.Remove(r.Path); err != nil {
		t.Fatal(err)
	}
	// A directory at the token path simulates a durable write failure.
	if err = os.Mkdir(filepath.Join(filepath.Dir(r.Path), "cloudflare.token"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = w.Apply(context.Background(), p, true); err == nil {
		t.Fatal("token write failure ignored")
	}
	if _, err = os.Stat(r.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published config without credentials")
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || journal.Phase != "approved" {
		t.Fatal("missing recovery journal", err)
	}
}
func TestCanceledSetupAndSymlinkRefused(t *testing.T) {
	w, r := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Prepare(ctx, r); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	p, err := w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Apply(ctx, p, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err = os.Symlink(target, filepath.Dir(r.Path)); err != nil {
		t.Fatal(err)
	}
	if err = w.Apply(context.Background(), p, true); err == nil {
		t.Fatal("followed installation symlink")
	}
	entries, _ := os.ReadDir(target)
	if len(entries) != 0 {
		t.Fatal("wrote outside deployment")
	}
}

func TestPreflightChecksEnabledListenersBeforeWriting(t *testing.T) {
	w, r := fixture(t)
	w.stunAvailable = func(context.Context, string, int) bool { return false }
	if _, err := w.Prepare(context.Background(), r); err == nil {
		t.Fatal("occupied STUN accepted")
	}
	off := false
	r.Config.STUN.Enabled = &off
	httpPort := 80
	r.Config.HTTP.Port = &httpPort
	w.portAvailable = func(_ context.Context, _ string, port int) bool { return port != 80 }
	if _, err := w.Prepare(context.Background(), r); err == nil {
		t.Fatal("occupied HTTP accepted")
	}
	if _, err := os.Stat(filepath.Dir(r.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight wrote files", err)
	}
}

func TestPreparedInstallationRetriesStartWithoutReinstalling(t *testing.T) {
	w, r := fixture(t)
	p, err := w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	p.Service, p.Start = true, true
	calls := 0
	w.install = func(context.Context, string, config.Settings) error { calls++; return nil }
	w.start = func(context.Context) error { return errors.New("injected start failure") }
	if err = w.Apply(context.Background(), p, true); err == nil {
		t.Fatal("start failure ignored")
	}
	before, err := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	p.original, err = os.ReadFile(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	w.start = func(context.Context) error {
		lock, err := state.Open(r.StateDir)
		if err != nil {
			return err
		}
		return lock.Close()
	}
	w.wait = func(context.Context, string, config.Settings) error { return nil }
	if err = w.Apply(context.Background(), p, true); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || journal.Phase != "ready" || calls != 1 || !bytes.Equal(before, after) {
		t.Fatal("resume recreated installation", journal.Phase, calls, err)
	}
}

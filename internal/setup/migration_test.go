package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/daemon"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
)

func TestInitializeMigrationPreservesIdentityAndRejectsForeignListener(t *testing.T) {
	w, r := fixture(t)
	region, listen := 902, ":8443"
	r.Overrides.Region, r.Overrides.Listen = &region, &listen
	r.Mode = PrepareService
	r.Sources.Identity = filepath.Join(t.TempDir(), "upstream.json")
	if _, err := state.Identity(r.Sources.Identity); err != nil {
		t.Fatal(err)
	}
	w.checkMigrationRegion = func(context.Context, config.Settings) error { return nil }
	w.portAvailable = func(context.Context, string, int) bool { return false }
	w.checkRelayIdentity = func(context.Context, config.Settings, []byte) error { return errors.New("wrong identity") }
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err == nil {
		t.Fatal("foreign listener accepted")
	}
	if _, err := os.Stat(r.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight wrote config")
	}
	w.checkRelayIdentity = func(context.Context, config.Settings, []byte) error { return nil }
	staged := false
	w.stage = func(context.Context, string, config.Settings) error { staged = true; return nil }
	w.install = func(context.Context, string, config.Settings) error {
		t.Fatal("migration enabled competing service")
		return nil
	}
	ui := &scriptedInteraction{t: t}
	result, err := w.Initialize(t.Context(), r, ui)
	if err != nil || result.Outcome != MigrationStaged {
		t.Fatal(result, err)
	}
	if !staged || !ui.displays[0].Summary.ExistingListener || ui.displays[0].Summary.Region != 902 {
		t.Fatal("migration was not staged", ui.displays)
	}
	original, err := os.ReadFile(r.Sources.Identity)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if err != nil || !bytes.Equal(original, imported) {
		t.Fatal("identity replaced", err)
	}
}

func TestInitializeImportsCertificateWithoutDisablingRenewal(t *testing.T) {
	w, r := fixture(t)
	cert := testutil.Cert(t, "relay.example.com", 42)
	r.Sources.ImportCertificate = filepath.Join(t.TempDir(), "cert.pem")
	r.Sources.ImportKey = filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(r.Sources.ImportCertificate, cert.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Sources.ImportKey, cert.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(r.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Resolve(loaded, r.ConfigPath)
	if err != nil || !s.AutomaticCertificate() {
		t.Fatal("renewal disabled", err)
	}
	status, err := certificate.CachedStatus(daemon.CertificateOptions(s, r.StateDir))
	if err != nil || !status.Valid || status.Serial != "42" {
		t.Fatal(status, err)
	}
}

func TestInitializeMigrationNeverOverwritesExistingIdentity(t *testing.T) {
	w, r := fixture(t)
	region := 902
	r.Overrides.Region = &region
	r.Sources.Identity = filepath.Join(t.TempDir(), "original.json")
	if _, err := state.Identity(r.Sources.Identity); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(r.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(r.StateDir, "identity.json")
	if _, err := state.Identity(target); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	w.checkMigrationRegion = func(context.Context, config.Settings) error { return nil }
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err == nil {
		t.Fatal("conflicting identity accepted")
	}
	after, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("identity overwritten", err)
	}
	if _, err := os.Stat(r.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("conflict replaced configuration", err)
	}
}

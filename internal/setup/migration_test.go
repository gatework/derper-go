package setup

import (
	"bytes"
	"context"
	"errors"
	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/daemon"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationPreservesIdentityAndRejectsForeignListener(t *testing.T) {
	w, r := fixture(t)
	r.Config.Region = 902
	r.Config.Relay.Listen = ":8443"
	r.IdentityPath = filepath.Join(t.TempDir(), "upstream.json")
	if _, err := state.Identity(r.IdentityPath); err != nil {
		t.Fatal(err)
	}
	w.checkMigrationRegion = func(context.Context, config.Settings) error { return nil }
	w.portAvailable = func(context.Context, string, int) bool { return false }
	w.checkRelayIdentity = func(context.Context, config.Settings, []byte) error { return errors.New("wrong identity") }
	if _, err := w.Prepare(context.Background(), r); err == nil {
		t.Fatal("foreign listener accepted")
	}
	if _, err := os.Stat(r.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight wrote config")
	}
	w.checkRelayIdentity = func(context.Context, config.Settings, []byte) error { return nil }
	p, err := w.Prepare(context.Background(), r)
	if err != nil || !p.ExistingListener || p.Config.Region != 902 {
		t.Fatal(p.Config, err)
	}
	p.Service = true
	staged := false
	w.stage = func(context.Context, string, config.Settings) error { staged = true; return nil }
	w.install = func(context.Context, string, config.Settings) error {
		t.Fatal("migration enabled competing service")
		return nil
	}
	if err = w.Apply(context.Background(), p, true); err != nil {
		t.Fatal(err)
	}
	if !staged {
		t.Fatal("migration was not staged")
	}
	original, _ := os.ReadFile(r.IdentityPath)
	imported, _ := os.ReadFile(filepath.Join(r.StateDir, "identity.json"))
	if !bytes.Equal(original, imported) {
		t.Fatal("identity replaced")
	}
}

func TestInitializationImportsCertificateWithoutDisablingRenewal(t *testing.T) {
	w, r := fixture(t)
	cert := testutil.Cert(t, r.Config.Domain, 42)
	r.ImportCertificate = filepath.Join(t.TempDir(), "cert.pem")
	r.ImportKey = filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(r.ImportCertificate, cert.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.ImportKey, cert.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Apply(context.Background(), p, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Resolve(loaded, r.Path)
	if err != nil || !s.AutomaticCertificate() {
		t.Fatal("renewal disabled", err)
	}
	status, err := certificate.CachedStatus(daemon.CertificateOptions(s, r.StateDir))
	if err != nil || !status.Valid || status.Serial != "42" {
		t.Fatal(status, err)
	}
}

func TestMigrationNeverOverwritesExistingIdentity(t *testing.T) {
	w, r := fixture(t)
	r.Config.Region = 902
	r.IdentityPath = filepath.Join(t.TempDir(), "original.json")
	if _, err := state.Identity(r.IdentityPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(r.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(r.StateDir, "identity.json")
	if _, err := state.Identity(target); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(target)
	w.checkMigrationRegion = func(context.Context, config.Settings) error { return nil }
	p, err := w.Prepare(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Apply(context.Background(), p, true); err == nil {
		t.Fatal("conflicting identity accepted")
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(before, after) {
		t.Fatal("identity overwritten")
	}
	if _, err = os.Stat(r.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("conflict replaced configuration")
	}
}

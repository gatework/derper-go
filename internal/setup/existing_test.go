package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
)

func TestInitializeExistingSourcesAreAssertions(t *testing.T) {
	w, r := fixture(t)
	cert := testutil.Cert(t, "relay.example.com", 1)
	r.Sources.ImportCertificate = filepath.Join(t.TempDir(), "source.pem")
	r.Sources.ImportKey = filepath.Join(t.TempDir(), "source.key")
	if err := state.Write(r.Sources.ImportCertificate, cert.CertPEM); err != nil {
		t.Fatal(err)
	}
	if err := state.Write(r.Sources.ImportKey, cert.KeyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(r.StateDir, "identity.json")
	identity, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	w.dnsPlan = nil // Existing deployment validation must not prepare again.
	w.terms = nil
	repeated := Request{ConfigPath: r.ConfigPath, Preview: true, Sources: r.Sources}
	repeated.Sources.Identity = identityPath
	if result, err := w.Initialize(t.Context(), repeated, &scriptedInteraction{t: t}); err != nil || result.Outcome != PreviewedDeployment {
		t.Fatal(result, err)
	}
	if err := state.Write(r.Sources.TokenFile, []byte("different-fixture-token")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Initialize(t.Context(), repeated, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "凭据与已有部署不同") || strings.Contains(err.Error(), "different-fixture-token") {
		t.Fatal(err)
	}
	if err := state.Write(r.Sources.TokenFile, []byte("secret-test-token")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other-identity.json")
	if _, err := state.Identity(other); err != nil {
		t.Fatal(err)
	}
	mismatch := repeated
	mismatch.Sources.Identity = other
	if _, err := w.Initialize(t.Context(), mismatch, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "身份与已有节点不同") {
		t.Fatal(err)
	}
	mismatch = repeated
	mismatch.Sources.ImportKey = ""
	if _, err := w.Initialize(t.Context(), mismatch, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "必须同时提供") {
		t.Fatal(err)
	}
	different := testutil.Cert(t, "relay.example.com", 2)
	if err := state.Write(r.Sources.ImportCertificate, different.CertPEM); err != nil {
		t.Fatal(err)
	}
	if err := state.Write(r.Sources.ImportKey, different.KeyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Initialize(t.Context(), repeated, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "证书与已有缓存不同") {
		t.Fatal(err)
	}
	mode := config.Public
	mismatch = Request{ConfigPath: r.ConfigPath, Preview: true, Overrides: Overrides{Admission: &mode}}
	if _, err := w.Initialize(t.Context(), mismatch, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "已有部署设置不同：admission.mode") {
		t.Fatal(err)
	}
	after, err := os.ReadFile(r.ConfigPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("assertion changed configuration", err)
	}
	after, err = os.ReadFile(identityPath)
	if err != nil || !bytes.Equal(identity, after) {
		t.Fatal("assertion changed identity", err)
	}
	journal, err := state.ReadDeployment(r.StateDir)
	if err != nil || journal.Phase != "prepared" {
		t.Fatal(journal, err)
	}
}

func TestInitializeEquivalentManualSourcesPreserveManagedPaths(t *testing.T) {
	w, r := manualInitialization(t)
	r.Mode = PrepareService
	w.paths = deploymentPaths{config: r.ConfigPath, state: filepath.Join(filepath.Dir(r.ConfigPath), "state")}
	w.checkHost = func() error { return nil }
	w.install = func(context.Context, string, config.Settings) error { return nil }
	w.ownState = func(string) error { return nil }
	if _, err := w.Initialize(t.Context(), r, &scriptedInteraction{t: t}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, overrides := range []Overrides{
		{CertificateFile: r.Overrides.CertificateFile},
		{CertificateKey: r.Overrides.CertificateKey},
		{CertificateFile: r.Overrides.CertificateFile, CertificateKey: r.Overrides.CertificateKey},
	} {
		request := Request{ConfigPath: r.ConfigPath, Preview: true, Overrides: overrides}
		if _, err := w.Initialize(t.Context(), request, &scriptedInteraction{t: t}); err != nil {
			t.Fatal("equivalent source rejected", err)
		}
	}
	after, err := os.ReadFile(r.ConfigPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeated sources replaced managed paths", err)
	}
	loaded, err := config.Load(r.ConfigPath)
	if err != nil || loaded.Certificate.File != "certificate.pem" || loaded.Certificate.Key != "certificate.key" {
		t.Fatal(loaded, err)
	}
	cert := testutil.Cert(t, "relay.example.com", 2)
	if err := state.Write(*r.Overrides.CertificateFile, cert.CertPEM); err != nil {
		t.Fatal(err)
	}
	if err := state.Write(*r.Overrides.CertificateKey, cert.KeyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Initialize(t.Context(), Request{ConfigPath: r.ConfigPath, Preview: true, Overrides: r.Overrides}, &scriptedInteraction{t: t}); err == nil || !strings.Contains(err.Error(), "手动证书与已有部署不同") {
		t.Fatal(err)
	}
}

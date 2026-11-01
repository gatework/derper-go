package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/daemon"
	"github.com/gatework/derper-go/internal/setup"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
)

func TestRepeatedInitializationValidatesExplicitSourcesWithoutResuming(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := setup.DataDir(path)
	if err := os.MkdirAll(data, 0700); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Domain: "relay.example.com", Email: "ops@example.com"}
	bytes, err := setup.ConfigBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Write(path, bytes); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveDeployment(data, state.Deployment{Config: bytes, ConfigHash: setup.Hash(bytes), Phase: "prepared"}); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Identity(filepath.Join(data, "identity.json")); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "input.token")
	deployed := filepath.Join(dir, "cloudflare.token")
	for _, file := range []string{token, deployed} {
		if err := state.Write(file, []byte("fixture-token\n")); err != nil {
			t.Fatal(err)
		}
	}
	cert := testutil.Cert(t, c.Domain, 1)
	certPath, keyPath := filepath.Join(dir, "source.pem"), filepath.Join(dir, "source.key")
	if err := state.Write(certPath, cert.CertPEM); err != nil {
		t.Fatal(err)
	}
	if err := state.Write(keyPath, cert.KeyPEM); err != nil {
		t.Fatal(err)
	}
	settings, err := c.Resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.Import(daemon.CertificateOptions(settings, data), certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	args := []string{"init", "--dry-run", "--config", path, "--token-file", token, "--identity", filepath.Join(data, "identity.json"), "--import-certificate", certPath, "--import-key", keyPath}
	if code, out, diagnostic := command(t, args...); code != 0 || !strings.Contains(out, "prepared") {
		t.Fatal(code, out, diagnostic)
	}
	journal, err := state.ReadDeployment(data)
	if err != nil || journal.Phase != "prepared" {
		t.Fatal(journal, err)
	}
	if err := state.Write(token, []byte("different-fixture-token")); err != nil {
		t.Fatal(err)
	}
	if code, _, diagnostic := command(t, args...); code != 1 || !strings.Contains(diagnostic, "凭据与已有部署不同") || strings.Contains(diagnostic, "different-fixture-token") {
		t.Fatal(code, diagnostic)
	}
	if err := state.Write(token, []byte("fixture-token")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other-identity.json")
	if _, err := state.Identity(other); err != nil {
		t.Fatal(err)
	}
	mismatched := append([]string{}, args...)
	for i, v := range mismatched {
		if v == "--identity" {
			mismatched[i+1] = other
		}
	}
	if code, _, diagnostic := command(t, mismatched...); code != 1 || !strings.Contains(diagnostic, "身份与已有节点不同") {
		t.Fatal(code, diagnostic)
	}
	different := testutil.Cert(t, c.Domain, 2)
	if err := state.Write(certPath, different.CertPEM); err != nil {
		t.Fatal(err)
	}
	if err := state.Write(keyPath, different.KeyPEM); err != nil {
		t.Fatal(err)
	}
	if code, _, diagnostic := command(t, args...); code != 1 || !strings.Contains(diagnostic, "证书与已有缓存不同") {
		t.Fatal(code, diagnostic)
	}
}

func TestServiceReloadRequiresStandardDeployment(t *testing.T) {
	if code, _, diagnostic := command(t, "service", "reload", "--dry-run", "-c", filepath.Join(t.TempDir(), "config.json")); code != 1 || !strings.Contains(diagnostic, "标准路径") {
		t.Fatal(code, diagnostic)
	}
}

func TestEquivalentManualCertificateSourcesPreserveManagedPaths(t *testing.T) {
	dir := t.TempDir()
	cert := testutil.Cert(t, "relay.example.com", 9)
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := state.Write(path, data); err != nil {
			t.Fatal(err)
		}
		return path
	}
	current := config.Settings{Domain: "relay.example.com", CertificateFile: write("managed.pem", cert.CertPEM), CertificateKey: write("managed.key", cert.KeyPEM)}
	requested := current
	requested.CertificateFile = write("source.pem", cert.CertPEM)
	requested.CertificateKey = write("source.key", cert.KeyPEM)
	checked, err := checkExistingInputs(current, requested, dir, existingInputs{manualCertificate: true, manualKey: true})
	if err != nil || len(config.ChangedFields(current, checked)) != 0 {
		t.Fatal(err)
	}
}

package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/testutil"
)

func TestInitializationPreviewDoesNotPersistOrNeedApproval(t *testing.T) {
	dir := t.TempDir()
	cert := testutil.Cert(t, "relay.example.com", 1)
	certPath, keyPath := filepath.Join(dir, "source.pem"), filepath.Join(dir, "source.key")
	if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "deployment", "config.json")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	args := []string{"init", "--no-service", "--no-dns", "--no-stun", "--admission", "public", "--listen", address, "--domain", "relay.example.com", "--certificate", certPath, "--key", keyPath, "-c", path, "--dry-run"}
	code, out, diagnostic := command(t, args...)
	if code != 0 || !strings.Contains(out, "只读预览完成") {
		t.Fatal(code, out, diagnostic)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("preview persisted deployment", err)
	}
}

func TestExplicitEmptyCredentialOrPathDoesNotFallBack(t *testing.T) {
	for _, args := range [][]string{{"init", "--token-file", ""}, {"init", "--config", ""}, {"config", "check", "--state-dir", ""}, {"certificate", "import", "--file", ""}} {
		if code, _, diagnostic := command(t, args...); code != 2 {
			t.Fatal(args, code, diagnostic)
		}
	}
}

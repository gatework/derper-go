package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/setup"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
)

func configFile(t *testing.T) (string, config.Config) {
	t.Helper()
	c := config.Config{Domain: "relay.example.com", Email: "ops@example.com"}
	p := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(c)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p, c
}
func command(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	n := Run(context.Background(), args, strings.NewReader(""), &out, &errOut)
	return n, out.String(), errOut.String()
}
func TestReadOnlyCommands(t *testing.T) {
	path, _ := configFile(t)
	for _, args := range [][]string{{}, {"--help"}, {"run", "--help"}, {"init", "--help"}, {"dns", "--help"}, {"version"}, {"config", "check", "-c", path}, {"config", "show", "-c", path}, {"config", "show", "--effective", "-c", path}, {"tailnet", "config", "-c", path}, {"service", "render", "-c", path}} {
		code, _, errOut := command(t, args...)
		if code != 0 {
			t.Fatalf("%v: %d %s", args, code, errOut)
		}
	}
	if _, err := os.Stat(setup.DataDir(path)); !os.IsNotExist(err) {
		t.Fatal("read-only command created state")
	}
	code, out, errOut := command(t, "tailnet", "config", "-c", path)
	if code != 0 || !strings.Contains(out, `"IPv6": "none"`) || !strings.Contains(out, `"DERPPort": 443`) {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
}
func TestOfflineMutationRejectsRunningOwner(t *testing.T) {
	path, _ := configFile(t)
	l, err := state.Open(setup.DataDir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	code, _, errOut := command(t, "certificate", "renew", "-c", path)
	if code == 0 || !strings.Contains(errOut, "in use") {
		t.Fatalf("%d %s", code, errOut)
	}
}
func TestAutomationRequiresExplicitConsentBeforeNetwork(t *testing.T) {
	for _, flags := range [][]string{{}, {"--yes"}, {"--accept-terms"}} {
		dir := t.TempDir()
		args := []string{"init", "--no-service", "-c", filepath.Join(dir, "config.json"), "--domain", "relay.example.com", "--email", "ops@example.com"}
		args = append(args, flags...)
		code, _, errOut := command(t, args...)
		if code == 0 || !strings.Contains(errOut, "非交互初始化") {
			t.Fatalf("%v: %d %s", flags, code, errOut)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Fatal("wrote before consent")
		}
	}
}
func TestInitForegroundIdempotent(t *testing.T) {
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
	t.Chdir(dir)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	args := []string{"init", "--listen", ":" + strconv.Itoa(port), "--no-service", "--yes", "--no-dns", "--no-stun", "--admission", "public", "--domain", "relay.example.com", "--certificate", "source.pem", "--key", "source.key", "-c", path}
	code, _, errOut := command(t, args...)
	if code != 0 {
		t.Fatal(errOut)
	}
	identity, err := os.ReadFile(filepath.Join(setup.DataDir(path), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut = command(t, args...)
	if code != 0 {
		t.Fatal(errOut)
	}
	after, _ := os.ReadFile(path)
	next, _ := os.ReadFile(filepath.Join(setup.DataDir(path), "identity.json"))
	if !bytes.Equal(before, after) || !bytes.Equal(identity, next) {
		t.Fatal("repeat init changed durable state")
	}
}
func TestTerminalEOFAndCancellation(t *testing.T) {
	var out bytes.Buffer
	ui := terminal{in: strings.NewReader(""), out: &out, err: &out, interactive: true}
	dir := t.TempDir()
	code := execute(context.Background(), []string{"init", "--no-service", "-c", filepath.Join(dir, "config.json")}, ui)
	if code == 0 {
		t.Fatal("EOF accepted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("EOF wrote state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := confirm(ctx, ui, "confirm"); err == nil {
		t.Fatal("cancellation accepted")
	}
}
func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"run", "--bad"}, {"version", "extra"}, {"certificate"}, {"server"}, {"wizard"}} {
		code, _, _ := command(t, args...)
		if code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
}

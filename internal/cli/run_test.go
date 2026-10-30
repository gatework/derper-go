package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/state"
)

func configFile(t *testing.T) (string, config.Config) {
	t.Helper()
	c := config.Default()
	c.Hostname = "relay.example.com"
	c.ACME.Email = "ops@example.com"
	c.ACME.AcceptTerms = true
	c.StateDir = filepath.Join(t.TempDir(), "state")
	c.Region = config.Region{ID: 900, Code: "test", Name: "test", Node: "test"}
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

func TestHelpCheckAndExportNeverCreateState(t *testing.T) {
	path, c := configFile(t)
	for _, args := range [][]string{{"--help"}, {"server", "--help"}, {"dns", "--help"}, {"version"}, {"check", "-c", path}, {"export-derpmap", "-c", path}} {
		code, _, errOut := command(t, args...)
		if code != 0 {
			t.Fatalf("%v: %d %s", args, code, errOut)
		}
	}
	if _, err := os.Stat(c.StateDir); !os.IsNotExist(err) {
		t.Fatal("read-only command created state")
	}
	code, out, errOut := command(t, "export-derpmap", "-c", path)
	if code != 0 || !strings.Contains(out, `"IPv6": "none"`) || !strings.Contains(out, `"DERPPort": 8443`) {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
}

func TestOfflineMutationRejectsRunningOwner(t *testing.T) {
	path, c := configFile(t)
	l, err := state.Acquire(c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	code, _, errOut := command(t, "cert", "renew", "-c", path)
	if code == 0 || !strings.Contains(errOut, "in use") {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestWizardExclusiveAndCredentialReference(t *testing.T) {
	file := filepath.Join(t.TempDir(), "server.json")
	args := []string{"wizard", "--hostname", "relay.example.com", "--email", "ops@example.com", "--ipv4", "192.0.2.1", "--token-file", "/etc/derper/cloudflare.token", "--accept-terms", "--output", file}
	code, _, errOut := command(t, args...)
	if code != 0 {
		t.Fatal(errOut)
	}
	if _, err := config.Load(file); err != nil {
		t.Fatal(err)
	}
	code, _, _ = command(t, args...)
	if code == 0 {
		t.Fatal("wizard replaced existing file")
	}
}

func TestSystemdRendering(t *testing.T) {
	c := config.Default()
	c.Cloudflare.TokenFile = "/etc/derper/cloudflare.token"
	unit, err := renderUnit("/usr/local/bin/derper-go", "/etc/derper/server.json", c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=derper", "LoadCredential=\"cloudflare-token:", "StateDirectory=derper", "ProtectSystem=strict", "tailscaled.service", "CapabilityBoundingSet=\n"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, path := range []string{"relative", "/tmp/a\nExecStart=evil", "/tmp/%n", "/tmp/$HOME"} {
		if _, err = renderUnit(path, "/etc/derper/server.json", c); err == nil {
			t.Fatalf("accepted unit injection %q", path)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"server", "--bad"}, {"version", "extra"}, {"cert"}} {
		code, _, _ := command(t, args...)
		if code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
}

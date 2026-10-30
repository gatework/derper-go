package systemd

import (
	"github.com/gatework/derper-go/internal/config"
	"strings"
	"testing"
)

func TestRenderSecurityAndReadiness(t *testing.T) {
	s, _ := (config.Config{Domain: "relay.example.com", Email: "ops@example.com"}).Resolve("/etc/derper-go")
	s.TokenFile = "/etc/derper-go/cloudflare.token"
	unit, err := Render(Binary, config.DefaultPath, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Type=notify", "TimeoutStartSec=15min", "User=derper-go", "StateDirectory=derper-go", "LoadCredential=\"cloudflare-token:", "ProtectSystem=strict", "tailscaled.service", "CAP_NET_BIND_SERVICE", " run --config "} {
		if !strings.Contains(unit, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, path := range []string{"relative", "/tmp/a\nExecStart=evil", "/tmp/%n", "/tmp/$HOME"} {
		if _, err = Render(path, config.DefaultPath, s); err == nil {
			t.Fatalf("accepted unit injection %q", path)
		}
	}
	s.Port = 8443
	s.CaptivePortal = false
	s.STUNPort = 3478
	unit, err = Render(Binary, config.DefaultPath, s)
	if err != nil || !strings.Contains(unit, "CapabilityBoundingSet=\n") {
		t.Fatal("unexpected bind capability", err)
	}
}

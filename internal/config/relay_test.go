package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCanonicalRelayConfigurationAndEffectiveRoundTrip(t *testing.T) {
	c, err := Decode([]byte(`{"domain":"relay.example.com","email":"ops@example.com","relay":{"listen":"[::1]:8443","connection_rate":{"per_second":2.5},"tcp":{"write_timeout":"0s"}},"http":{"port":8080},"admission":{"max_concurrent_checks":8}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.HTTPSAddress() != "[::1]:8443" || s.STUNAddress() != "[::1]:3478" || s.HTTPPort != 8080 || s.TCPWriteTimeout != 0 || s.TCPKeepalive != 10*time.Minute || s.TCPUserTimeout != 15*time.Second || s.ConnectionBurst != 3 || s.MaxConcurrentChecks != 8 {
		t.Fatal(s)
	}
	effective, err := c.Effective(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(b); err != nil {
		t.Fatalf("effective config cannot be reused: %s: %v", b, err)
	}
}
func TestRejectAmbiguousAndUnsafeConfiguration(t *testing.T) {
	for _, fragment := range []string{
		`"port":443`, `"access":"public"`, `"captive_portal":true`, `"tailscale":{"max_concurrent_checks":8}`,
		`"relay":{"listen":"relay.example.com:443"}`, `"relay":{"listen":":0"}`,
		`"relay":{"tcp":{"write_timeout":2}}`, `"relay":{"tcp":{"user_timeout":"-1s"}}`,
		`"relay":{"connection_rate":{"burst":10}}`, `"relay":{"listen":":80"},"http":{"port":80}`,
		`"admission":{"mode":"public","url":"https://controller.example.com"}`,
		`"admission":{"mode":"controller","url":"http://192.0.2.1/verify"}`,
		`"admission":{"timeout":"10s"}`, `"admission":{"blocked_apps":["x","x"]}`,
		`"mesh":{"peers":[{"host":"peer.example.com"}]}`,
		`"mesh":{"key_file":"key","peers":[{"host":"peer.example.com:"}]}`,
		`"relay":{"enabled":false}`,
		`"bootstrap_dns":{"names":["same.example.com"],"unlisted":[{"name":"same.example.com"}]}`,
	} {
		if _, err := Decode([]byte(`{"domain":"relay.example.com","email":"ops@example.com",` + fragment + `}`)); err == nil {
			t.Fatal("accepted", fragment)
		}
	}
}
func TestControllerModeAndBootstrapOnlyDefaults(t *testing.T) {
	c, err := Decode([]byte(`{"domain":"relay.example.com","email":"ops@example.com","admission":{"url":"http://127.0.0.1:9090/verify"}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Resolve(t.TempDir())
	if err != nil || s.Access != Controller || s.AdmissionFailOpen {
		t.Fatal(s, err)
	}
	c, err = Decode([]byte(`{"domain":"relay.example.com","email":"ops@example.com","relay":{"enabled":false},"bootstrap_dns":{"names":["Control.Example.com."]}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err = c.Resolve(t.TempDir())
	if err != nil || s.RelayEnabled || s.BootstrapNames[0] != "control.example.com" {
		t.Fatal(s, err)
	}
}

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestBootstrapNeverLeaksHiddenNamesOrResolvesRequestInput(t *testing.T) {
	s := New(Options{Names: []string{"public.example.com"}, Unlisted: []Name{{Name: "hidden.example.com", RolloutRecord: "rollout.example.com"}}})
	var lookups atomic.Int32
	percent := "0"
	s.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{percent}, nil }
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	query := func(path string) map[string][]string {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "192.0.2.2:1234"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var out map[string][]string
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, path := range []string{"/bootstrap-dns", "/bootstrap-dns?q=attacker.example.com", "/bootstrap-dns?q=hidden.example.com"} {
		out := query(path)
		if _, ok := out["hidden.example.com"]; ok {
			t.Fatal("hidden response leaked", path)
		}
	}
	if lookups.Load() != 2 {
		t.Fatal("HTTP request triggered DNS", lookups.Load())
	}
	percent = "100"
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := query("/bootstrap-dns?q=hidden.example.com")
	if len(out) != 1 || len(out["hidden.example.com"]) != 1 {
		t.Fatal("targeted response", out)
	}
}
func TestRefreshFailurePreservesKnownAddresses(t *testing.T) {
	s := New(Options{Names: []string{"control.example.com"}})
	s.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	previous := string(s.current.Load().Public)
	s.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("resolver unavailable")
	}
	if err := s.refresh(context.Background()); err == nil {
		t.Fatal("resolver failure lost")
	}
	if string(s.current.Load().Public) != previous {
		t.Fatal("temporary outage erased valid cache")
	}
}
func TestRolloutFailClosedAndStableSourceSelection(t *testing.T) {
	for _, values := range [][]string{nil, {"-1"}, {"101"}, {"50", "100"}, {"bad"}} {
		if rollout(values) != 0 {
			t.Fatal(values)
		}
	}
	for _, remote := range []string{"192.0.2.1:1234", "[2001:db8::1]:1234"} {
		if matches(remote, 0) || !matches(remote, 100) {
			t.Fatal("percentage boundary")
		}
		host, _, err := net.SplitHostPort(remote)
		if err != nil {
			t.Fatal(err)
		}
		if matches(remote, 50) != matches(net.JoinHostPort(host, "65535"), 50) {
			t.Fatal("unstable assignment")
		}
	}
	if matches("invalid", 50) {
		t.Fatal("invalid source accepted")
	}
}

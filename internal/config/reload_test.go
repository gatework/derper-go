package config

import (
	"reflect"
	"testing"
	"time"
)

func TestCombinedAdmissionAndCapacity(t *testing.T) {
	c, err := Decode([]byte(`{"domain":"relay.example.com","email":"ops@example.com","admission":{"mode":"tailnet","url":"https://access.example.com","max_requests":8}}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Resolve(t.TempDir())
	if err != nil || !s.UsesTailnet() || !s.UsesController() || s.MaxConcurrentChecks != 8 || s.MaxAdmissionRequests != 8 {
		t.Fatal(s, err)
	}
	for _, text := range []string{`{"max_requests":8193}`, `{"max_requests":4,"max_concurrent_checks":8}`, `{"mode":"public","url":"https://access.example.com"}`} {
		if _, err := Decode([]byte(`{"domain":"relay.example.com","email":"ops@example.com","admission":` + text + `}`)); err == nil {
			t.Fatal("unsafe capacity or policy", text)
		}
	}
}

func TestReloadRejectsStructuralChanges(t *testing.T) {
	old, err := (Config{Domain: "relay.example.com", Email: "ops@example.com"}).Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	next := old
	next.MaxConnections = 4096
	next.Homepage = "https://example.com"
	next.AdmissionTimeout = time.Second
	if err := CheckReload(old, next); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Settings){
		func(s *Settings) { s.Port++ }, func(s *Settings) { s.Access = Public }, func(s *Settings) { s.AdmissionURL = "https://access.example.com" },
		func(s *Settings) { s.MaxAdmissionRequests++ }, func(s *Settings) { s.Socket = "/other.sock" }, func(s *Settings) { s.CA = "https://other.example.com" },
	} {
		next = old
		change(&next)
		if CheckReload(old, next) == nil {
			t.Fatal("structural change accepted")
		}
	}
}

func TestEverySettingHasAnOperatorFieldName(t *testing.T) {
	typ := reflect.TypeFor[Settings]()
	for i := 0; i < typ.NumField(); i++ {
		if settingPaths[typ.Field(i).Name] == "" {
			t.Errorf("missing operator name for %s", typ.Field(i).Name)
		}
	}
}

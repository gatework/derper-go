package dns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
)

type fakeAPI struct {
	records               []cloudflare.Record
	creates, patches      int
	loseCreate, losePatch bool
}

func (f *fakeAPI) CheckZone(ctx context.Context, _ string) error { return ctx.Err() }
func (f *fakeAPI) Records(ctx context.Context, _ string) ([]cloudflare.Record, error) {
	return append([]cloudflare.Record(nil), f.records...), ctx.Err()
}
func (f *fakeAPI) Create(ctx context.Context, r cloudflare.Record) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.creates++
	r.ID = fmt.Sprint(f.creates)
	f.records = append(f.records, r)
	if f.loseCreate {
		f.loseCreate = false
		return "", errors.New("response lost after commit")
	}
	return r.ID, nil
}
func (f *fakeAPI) Patch(ctx context.Context, id string, fields any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.patches++
	m := fields.(map[string]any)
	for i, r := range f.records {
		if r.ID == id {
			r.Content = m["content"].(string)
			r.TTL = m["ttl"].(int)
			r.Proxied = m["proxied"].(bool)
			r.Comment = m["comment"].(string)
			f.records[i] = r
		}
	}
	if f.losePatch {
		f.losePatch = false
		return errors.New("response lost after update")
	}
	return nil
}
func controller(t *testing.T) (*Controller, *fakeAPI) {
	t.Helper()
	c := config.Default()
	c.Hostname = "relay.example.com"
	c.StateDir = t.TempDir()
	c.DNS.Mode = "manage"
	c.DNS.IPv4 = "192.0.2.1"
	f := new(fakeAPI)
	return &Controller{Config: c, API: f, HTTP: http.DefaultClient}, f
}

func TestPlanIsReadOnlyAndApplyIsIdempotent(t *testing.T) {
	c, f := controller(t)
	c.Config.StateDir = filepath.Join(c.Config.StateDir, "absent")
	plan, err := c.Plan(context.Background())
	if err != nil || len(plan) != 1 || plan[0].Action != "create" {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	if _, err = os.Stat(c.Config.StateDir); !os.IsNotExist(err) {
		t.Fatal("plan wrote state")
	}
	if f.creates+f.patches != 0 {
		t.Fatal("plan wrote DNS")
	}
	if err = os.Mkdir(c.Config.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	c.Config.DNS.IPv6 = "2001:db8::1"
	if _, err = c.Apply(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Apply(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if f.creates != 2 || f.patches != 0 {
		t.Fatalf("writes=%d/%d", f.creates, f.patches)
	}
	for _, r := range f.records {
		if r.Proxied || r.Comment == "" {
			t.Fatal("unsafe address publication")
		}
	}
}

func TestAdoptionAndExternalMutation(t *testing.T) {
	c, f := controller(t)
	f.records = []cloudflare.Record{{ID: "existing", Type: "A", Name: c.Config.Hostname, Content: c.Config.DNS.IPv4, TTL: 1}, {ID: "txt", Type: "TXT", Name: c.Config.Hostname, Content: "unrelated"}}
	if _, err := c.Apply(context.Background(), ""); err == nil {
		t.Fatal("silently adopted foreign record")
	}
	if f.patches != 0 {
		t.Fatal("unauthorized change")
	}
	if _, err := c.Apply(context.Background(), "existing"); err != nil {
		t.Fatal(err)
	}
	if f.records[1].Content != "unrelated" {
		t.Fatal("changed unrelated record")
	}
	f.records[0].Content = "192.0.2.99"
	if _, err := c.Apply(context.Background(), ""); err == nil {
		t.Fatal("overwrote external modification")
	}
	if f.patches != 1 {
		t.Fatal("unexpected patch")
	}
}

func TestLostCreateAndUpdateResponsesRecover(t *testing.T) {
	c, f := controller(t)
	f.loseCreate = true
	if _, err := c.Apply(context.Background(), ""); err == nil {
		t.Fatal("missing create error")
	}
	if _, err := c.Apply(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if f.creates != 1 {
		t.Fatal("duplicated uncertain create")
	}
	c.Config.DNS.IPv4 = "192.0.2.2"
	f.losePatch = true
	if _, err := c.Apply(context.Background(), ""); err == nil {
		t.Fatal("missing update error")
	}
	if _, err := c.Apply(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if f.patches != 1 {
		t.Fatal("duplicated uncertain update")
	}
	if _, err := c.Apply(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestDualStackAdoptionRequiresAllRecordIDsBeforeWriting(t *testing.T) {
	c, f := controller(t)
	c.Config.DNS.IPv6 = "2001:db8::1"
	f.records = []cloudflare.Record{
		{ID: "v4", Type: "A", Name: c.Config.Hostname, Content: c.Config.DNS.IPv4, TTL: 1},
		{ID: "v6", Type: "AAAA", Name: c.Config.Hostname, Content: c.Config.DNS.IPv6, TTL: 1},
	}
	if _, err := c.Apply(context.Background(), "v4"); err == nil {
		t.Fatal("partial adoption accepted")
	}
	if f.patches != 0 {
		t.Fatal("partially changed DNS before validating all adoptions")
	}
	if _, err := c.Apply(context.Background(), "v4", "v6"); err != nil {
		t.Fatal(err)
	}
	if f.patches != 2 {
		t.Fatalf("patches=%d, want 2", f.patches)
	}
	if _, err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.patches != 2 {
		t.Fatal("adopted records are not idempotent")
	}
}

func TestDNSConflicts(t *testing.T) {
	for _, kind := range []string{"CNAME", "NS", "multiple", "other-name"} {
		t.Run(kind, func(t *testing.T) {
			c, f := controller(t)
			r := cloudflare.Record{ID: "one", Type: kind, Name: c.Config.Hostname}
			if kind == "multiple" {
				r.Type = "A"
				f.records = append(f.records, r)
			}
			if kind == "other-name" {
				r.Type = "A"
				r.Name = "other.example.com"
			}
			f.records = append(f.records, r)
			if _, err := c.Apply(context.Background(), ""); err == nil {
				t.Fatal("conflict accepted")
			}
			if f.creates+f.patches != 0 {
				t.Fatal("conflict mutated DNS")
			}
		})
	}
}

func TestDiscoveryFailurePreservesRecords(t *testing.T) {
	c, f := controller(t)
	var value atomic.Value
	value.Store("192.0.2.1")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, value.Load()) }))
	defer srv.Close()
	c.Config.DNS.IPv4 = ""
	c.Config.DNS.IPv4URL = srv.URL
	c.HTTP = srv.Client()
	if _, err := c.Apply(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	value.Store("127.0.0.1")
	if _, err := c.Apply(context.Background(), ""); err == nil {
		t.Fatal("invalid discovery accepted")
	}
	if f.patches != 0 || f.records[0].Content != "192.0.2.1" {
		t.Fatal("lost last good DNS")
	}
}

func TestObserveCannotApply(t *testing.T) {
	c, f := controller(t)
	c.Config.DNS.Mode = "observe"
	if _, err := c.Apply(context.Background(), ""); err == nil {
		t.Fatal("observe wrote state")
	}
	if f.creates+f.patches != 0 {
		t.Fatal("observe wrote DNS")
	}
}

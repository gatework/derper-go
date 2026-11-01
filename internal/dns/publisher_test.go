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
)

type fakeAPI struct {
	createError           error
	records               []cloudflare.Record
	creates, patches      int
	loseCreate, losePatch bool
}

func (f *fakeAPI) CheckZone(ctx context.Context, _ string) error { return ctx.Err() }
func (f *fakeAPI) ListRecords(ctx context.Context, _ string) ([]cloudflare.Record, error) {
	return append([]cloudflare.Record(nil), f.records...), ctx.Err()
}
func (f *fakeAPI) CreateRecord(ctx context.Context, r cloudflare.Record) (string, error) {
	if f.createError != nil {
		return "", f.createError
	}
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
func (f *fakeAPI) UpdateRecord(ctx context.Context, id string, fields cloudflare.RecordUpdate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.patches++
	for i, r := range f.records {
		if r.ID == id {
			r.Content = fields.Content
			r.TTL = fields.TTL
			r.Proxied = fields.Proxied
			r.Comment = fields.Comment
			f.records[i] = r
		}
	}
	if f.losePatch {
		f.losePatch = false
		return errors.New("response lost after update")
	}
	return nil
}
func publisher(t *testing.T) (*Publisher, *fakeAPI) {
	t.Helper()
	f := new(fakeAPI)
	return New(Options{Domain: "relay.example.com", StateDir: t.TempDir(), Publish: true, IPv4: "192.0.2.1"}, f), f

}

func TestPlanIsReadOnlyAndApplyIsIdempotent(t *testing.T) {
	c, f := publisher(t)
	c.options.StateDir = filepath.Join(c.options.StateDir, "absent")
	plan, err := c.Plan(context.Background())
	if err != nil || len(plan) != 1 || plan[0].Action != "create" {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	if _, err = os.Stat(c.options.StateDir); !os.IsNotExist(err) {
		t.Fatal("plan wrote state")
	}
	if f.creates+f.patches != 0 {
		t.Fatal("plan wrote DNS")
	}
	if err = os.Mkdir(c.options.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	c.options.IPv6 = "2001:db8::1"
	if _, err = c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Apply(context.Background()); err != nil {
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
	c, f := publisher(t)
	f.records = []cloudflare.Record{{ID: "existing", Type: "A", Name: c.options.Domain, Content: c.options.IPv4, TTL: 1}, {ID: "txt", Type: "TXT", Name: c.options.Domain, Content: "unrelated"}}
	if _, err := c.Apply(context.Background()); err == nil {
		t.Fatal("silently adopted foreign record")
	}
	if f.patches != 0 {
		t.Fatal("unauthorized change")
	}
	if _, err := c.Apply(context.Background(), f.records[0]); err != nil {
		t.Fatal(err)
	}
	if f.records[1].Content != "unrelated" {
		t.Fatal("changed unrelated record")
	}
	f.records[0].Content = "192.0.2.99"
	if _, err := c.Apply(context.Background()); err == nil {
		t.Fatal("overwrote external modification")
	}
	if f.patches != 1 {
		t.Fatal("unexpected patch")
	}
}

func TestLostCreateAndUpdateResponsesRecover(t *testing.T) {
	c, f := publisher(t)
	f.loseCreate = true
	if _, err := c.Apply(context.Background()); err == nil {
		t.Fatal("missing create error")
	}
	if _, err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.creates != 1 {
		t.Fatal("duplicated uncertain create")
	}
	c.options.IPv4 = "192.0.2.2"
	f.losePatch = true
	if _, err := c.Apply(context.Background()); err == nil {
		t.Fatal("missing update error")
	}
	if _, err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.patches != 1 {
		t.Fatal("duplicated uncertain update")
	}
	if _, err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDualStackAdoptionRequiresAllRecordIDsBeforeWriting(t *testing.T) {
	c, f := publisher(t)
	c.options.IPv6 = "2001:db8::1"
	f.records = []cloudflare.Record{
		{ID: "v4", Type: "A", Name: c.options.Domain, Content: c.options.IPv4, TTL: 1},
		{ID: "v6", Type: "AAAA", Name: c.options.Domain, Content: c.options.IPv6, TTL: 1},
	}
	if _, err := c.Apply(context.Background(), f.records[0]); err == nil {
		t.Fatal("partial adoption accepted")
	}
	if f.patches != 0 {
		t.Fatal("partially changed DNS before validating all adoptions")
	}
	if _, err := c.Apply(context.Background(), f.records[0], f.records[1]); err != nil {
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
			c, f := publisher(t)
			r := cloudflare.Record{ID: "one", Type: kind, Name: c.options.Domain}
			if kind == "multiple" {
				r.Type = "A"
				f.records = append(f.records, r)
			}
			if kind == "other-name" {
				r.Type = "A"
				r.Name = "other.example.com"
			}
			f.records = append(f.records, r)
			if _, err := c.Apply(context.Background()); err == nil {
				t.Fatal("conflict accepted")
			}
			if f.creates+f.patches != 0 {
				t.Fatal("conflict mutated DNS")
			}
		})
	}
}

func TestDiscoveryFailurePreservesRecords(t *testing.T) {
	c, f := publisher(t)
	var value atomic.Value
	value.Store("192.0.2.1")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, value.Load()) }))
	defer srv.Close()
	c.options.IPv4 = ""
	c.options.AutoIPv4 = true
	c.discover = func(ctx context.Context) (string, error) { return discoverIPv4(ctx, srv.Client(), []string{srv.URL}) }
	if _, err := c.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	value.Store("127.0.0.1")
	if _, err := c.Apply(context.Background()); err == nil {
		t.Fatal("invalid discovery accepted")
	}
	if f.patches != 0 || f.records[0].Content != "192.0.2.1" {
		t.Fatal("lost last good DNS")
	}
}

func TestObserveCannotApply(t *testing.T) {
	c, f := publisher(t)
	c.options.Publish = false
	if _, err := c.Apply(context.Background()); err == nil {
		t.Fatal("observe wrote state")
	}
	if f.creates+f.patches != 0 {
		t.Fatal("observe wrote DNS")
	}
}

func TestApprovedSnapshotCannotAuthorizeConcurrentMutation(t *testing.T) {
	c, f := publisher(t)
	f.records = []cloudflare.Record{{ID: "existing", Type: "A", Name: c.options.Domain, Content: "192.0.2.9", TTL: 1}}
	changes, err := c.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	approved := *changes[0].Before
	f.records[0].Content = "192.0.2.10"
	if _, err = c.Apply(context.Background(), approved); err == nil {
		t.Fatal("adopted changed record")
	}
	if f.creates+f.patches != 0 {
		t.Fatal("wrote before validating snapshot")
	}
	f.records[0].Comment = "derper-go:foreign:A"
	if _, err = c.Plan(context.Background()); err == nil {
		t.Fatal("offered adoption of foreign-owned record")
	}
}

func TestUnsentWriteDoesNotRetainPendingIntent(t *testing.T) {
	c, api := publisher(t)
	api.createError = &cloudflare.NotSentError{Cause: errors.New("credential unavailable")}
	_, err := c.Apply(t.Context())
	if err == nil || errors.Is(err, cloudflare.ErrUncertainWrite) {
		t.Fatal(err)
	}
	j, readErr := c.load()
	if readErr != nil || len(j.Pending) != 0 || api.creates != 0 {
		t.Fatal(j, readErr)
	}
	api.createError = nil
	if _, err := c.Apply(t.Context()); err != nil || api.creates != 1 {
		t.Fatal(err, api.creates)
	}
}

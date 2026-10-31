package admission

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"testing"
	"time"
)

type checkFunc func(context.Context, tailcfg.DERPAdmitClientRequest) error

func (f checkFunc) VerifyClient(ctx context.Context, r tailcfg.DERPAdmitClientRequest) error {
	return f(ctx, r)
}

func TestChainDenialCannotBeOverriddenByFailOpen(t *testing.T) {
	var calls atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer remote.Close()
	controller := New(Options{URL: remote.URL, FailOpen: true})
	defer controller.Close()
	denied := errors.New("node absent from Tailnet")
	local := checkFunc(func(context.Context, tailcfg.DERPAdmitClientRequest) error { return denied })
	request := tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()}
	if err := All(2, local, controller).VerifyClient(context.Background(), request); !errors.Is(err, denied) || calls.Load() != 0 {
		t.Fatal("local denial bypassed", err)
	}
	local = func(context.Context, tailcfg.DERPAdmitClientRequest) error { return nil }
	if err := All(2, local, controller).VerifyClient(context.Background(), request); err != nil || calls.Load() != 1 {
		t.Fatal("explicit outage fallback failed", err)
	}
}

func TestChainTotalQuotaAndCancellation(t *testing.T) {
	entered := make(chan struct{})
	check := checkFunc(func(ctx context.Context, _ tailcfg.DERPAdmitClientRequest) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	chain := All(1, check)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- chain.VerifyClient(ctx, tailcfg.DERPAdmitClientRequest{}) }()
	<-entered
	if err := chain.VerifyClient(context.Background(), tailcfg.DERPAdmitClientRequest{}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(chain.requests) != 0 {
		t.Fatal("quota leaked")
	}
}

func TestControllerReloadKeepsInflightPolicySnapshot(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(503) }))
	defer old.Close()
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"Allow":true}`)) }))
	defer next.Close()
	c := New(Options{URL: old.URL, MaxRequests: 4, MaxConcurrentChecks: 2})
	defer c.Close()
	request := tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()}
	done := make(chan error, 1)
	go func() { done <- c.VerifyClient(context.Background(), request) }()
	<-entered
	c.UpdatePolicy(next.URL, true, time.Second)
	if err := c.VerifyClient(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrUnavailable) {
		t.Fatal("in-flight request adopted new fallback", err)
	}
}

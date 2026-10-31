package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestControllerPreservesSourceAndRefusesExplicitDenial(t *testing.T) {
	request := tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public(), Source: netip.MustParseAddr("192.0.2.7")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Error("method", r.Method)
		}
		var got tailcfg.DERPAdmitClientRequest
		if json.NewDecoder(r.Body).Decode(&got) != nil || got != request {
			t.Error("lost admission context", got)
		}
		fmt.Fprint(w, `{"Allow":false}`)
	}))
	defer server.Close()
	controller := New(Options{URL: server.URL, FailOpen: true})
	defer controller.Close()
	if err := controller.VerifyClient(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatal("fail-open overrode refusal", err)
	}
	if controller.Stats().FailOpen != 0 {
		t.Fatal("denial counted as outage")
	}
}
func TestControllerUnavailablePolicyAndResponseRedaction(t *testing.T) {
	for _, body := range []string{`{"echo":"private-value"}`, `null`, strings.Repeat("x", 5000)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		for _, open := range []bool{false, true} {
			controller := New(Options{URL: server.URL, FailOpen: open})
			err := controller.VerifyClient(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
			if (err == nil) != open {
				t.Fatal("wrong outage policy", open, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-value") {
				t.Fatal("body exposed")
			}
			if controller.Error() == nil {
				t.Fatal("outage was not observable")
			}
			controller.Close()
		}
		server.Close()
	}
}
func TestControllerCancellationAlwaysFailsClosed(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	controller := New(Options{URL: server.URL, FailOpen: true})
	defer controller.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- controller.VerifyClient(ctx, tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	controller.Close()
	if controller.Stats().Running != 0 || controller.Stats().Requests != 0 {
		t.Fatal("requests retained")
	}
	if err := controller.VerifyClient(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
func TestControllerDoesNotFollowRedirects(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer redirect.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, redirect.URL, http.StatusFound) }))
	defer server.Close()
	controller := New(Options{URL: server.URL, Timeout: time.Second})
	defer controller.Close()
	if err := controller.VerifyClient(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestControllerBoundsRequestsAndJoinsCanceledWork(t *testing.T) {
	started := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	controller := New(Options{URL: server.URL, MaxConcurrentChecks: 2, FailOpen: true})
	defer controller.Close()
	results := make(chan error, 8)
	for range 8 {
		go func() {
			results <- controller.VerifyClient(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
		}()
	}
	<-started
	<-started
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for controller.Stats().Requests != 8 {
		select {
		case <-deadline.C:
			t.Fatal("requests were not bounded/queued")
		case <-poll.C:
		}
	}
	if s := controller.Stats(); s.Running != 2 || s.PeakRunning != 2 {
		t.Fatal(s)
	}
	controller.Close()
	for range 8 {
		if err := <-results; err == nil {
			t.Fatal("shutdown allowed a connection")
		}
	}
	if s := controller.Stats(); s.Requests != 0 || s.Running != 0 {
		t.Fatal("work retained after Close", s)
	}
}

func TestControllerTimeoutFallbackIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); <-r.Context().Done() }))
	defer server.Close()
	for _, open := range []bool{false, true} {
		c := New(Options{URL: server.URL, FailOpen: open, Timeout: 20 * time.Millisecond})
		err := c.VerifyClient(context.Background(), tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public()})
		if (err == nil) != open {
			t.Fatal("timeout fallback", open, err)
		}
		c.Close()
	}
}

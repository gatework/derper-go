package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestErrorRedactionAndRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing authorization")
		}
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1015,"message":"secret"}]}`)
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, token: "secret", zoneID: "zone", http: srv.Client()}
	_, err := c.ListRecords(context.Background(), "relay.example.com")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != 429 || apiErr.RetryAfter != 2*time.Minute {
		t.Fatalf("error=%v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("error exposed response body")
	}
}

func TestPaginationAndZoneDiscovery(t *testing.T) {
	var queries atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zones" {
			if r.URL.Query().Get("name") == "example.com" {
				fmt.Fprint(w, `{"success":true,"result":[{"id":"zone","name":"example.com","status":"active"}]}`)
			} else {
				fmt.Fprint(w, `{"success":true,"result":[]}`)
			}
			return
		}
		queries.Add(1)
		fmt.Fprintf(w, `{"success":true,"result":[{"id":%q,"name":"relay.example.com","type":"TXT"}],"result_info":{"total_pages":2}}`, r.URL.Query().Get("page"))
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, token: "secret", http: srv.Client()}
	if err := c.CheckZone(context.Background(), "relay.example.com"); err != nil {
		t.Fatal(err)
	}
	records, err := c.ListRecords(context.Background(), "relay.example.com")
	if err != nil || len(records) != 2 || queries.Load() != 2 {
		t.Fatalf("records=%v calls=%v err=%v", records, queries.Load(), err)
	}
}

func TestCredentialsRotateAndCanceledRequest(t *testing.T) {
	token := "first"
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Authorization")
		fmt.Fprint(w, `{"success":true,"result":[]}`)
	}))
	defer srv.Close()
	c := NewSource(func() (string, error) { return token, nil }, "zone", srv.Client())
	c.baseURL = srv.URL
	if _, err := c.ListRecords(context.Background(), "relay.example.com"); err != nil {
		t.Fatal(err)
	}
	token = "second"
	if _, err := c.ListRecords(context.Background(), "relay.example.com"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListRecords(ctx, "relay.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if len(got) != 2 || <-got != "Bearer first" || <-got != "Bearer second" {
		t.Fatal("credentials were not rotated")
	}
}

func TestResponseSizeBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", (1<<20)+1)) }))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, http: srv.Client()}
	if _, err := c.ListRecords(context.Background(), "relay.example.com"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}

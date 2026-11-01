package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("fixture-secret") }
func (failingBody) Close() error             { return nil }

func TestPreparationFailureCannotBeAnUncertainWrite(t *testing.T) {
	calls := 0
	c := NewSource(func() (string, error) { return "", errors.New("credential unavailable") }, "zone", &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected send") })})
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		if canceled {
			cancel()
		}
		defer cancel()
		_, err := c.CreateRecord(ctx, Record{})
		var unsent *NotSentError
		if !errors.As(err, &unsent) || errors.Is(err, ErrUncertainWrite) || calls != 0 {
			t.Fatal(err, calls)
		}
	}
	c.tokenSource = nil
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := c.CreateRecord(ctx, Record{})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrUncertainWrite) || calls != 0 {
		t.Fatal(err, calls)
	}
	for _, cause := range []error{nil, context.Canceled} {
		err := &UncertainError{Cause: cause}
		if !errors.Is(err, ErrUncertainWrite) {
			t.Fatal(err)
		}
		for _, child := range err.Unwrap() {
			if child == nil {
				t.Fatal("nil child")
			}
		}
	}
}
func TestQueryBudgetIncludesEnvelope(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprintf(w, `{"success":true,"result":[{"id":"%d","name":"relay.example.com","type":"TXT"}],"padding":"%s","result_info":{"total_pages":30}}`, calls, strings.Repeat("x", 900<<10))
	}))
	defer server.Close()
	c := New("fixture", "zone", server.Client())
	c.baseURL = server.URL
	if _, err := c.ListRecords(t.Context(), "relay.example.com"); err == nil || calls > 19 {
		t.Fatal(err, calls)
	}
}
func TestResponseFailuresPreserveRetryTimingWithoutBodyErrors(t *testing.T) {
	for _, body := range []io.ReadCloser{failingBody{}, io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1)))} {
		c := New("fixture", "zone", &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": {"60"}}, Body: body, Request: r}, nil
		})})
		err := c.DeleteRecord(t.Context(), "record")
		var api *Error
		if !errors.Is(err, ErrUncertainWrite) || !errors.As(err, &api) || api.Status != 503 || api.RetryAfter != time.Minute || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal(err)
		}
	}
}

type borrowedTransport struct{ closed int }

func (*borrowedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}
func (t *borrowedTransport) CloseIdleConnections() { t.closed++ }
func TestTransportOwnership(t *testing.T) {
	shared := &borrowedTransport{}
	old := http.DefaultTransport
	http.DefaultTransport = shared
	defer func() { http.DefaultTransport = old }()
	borrowed := New("fixture", "zone", &http.Client{Transport: shared})
	borrowed.Close()
	owned := New("fixture", "zone", nil)
	owned.Close()
	if shared.closed != 0 || owned.http.Transport == shared {
		t.Fatal("closed a borrowed transport", shared.closed)
	}
}

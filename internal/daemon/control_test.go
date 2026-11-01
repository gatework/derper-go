package daemon

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func controlDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dgr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Mkdir(filepath.Join(dir, "run"), 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestConcurrentReloadRefusesQueueAndShutdownCancelsJob(t *testing.T) {
	dir := controlDirectory(t)
	path := filepath.Join(dir, "config.json")
	entered := make(chan struct{})
	stop, err := startReloadControl(dir, path, func(ctx context.Context, _ bool) (ReloadPlan, error) {
		close(entered)
		<-ctx.Done()
		return ReloadPlan{}, ctx.Err()
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	done := make(chan error, 1)
	go func() { done <- Reload(t.Context(), dir, path) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reload did not start")
	}
	if err := Reload(t.Context(), dir, path); err == nil {
		t.Fatal("concurrent reload queued")
	}
	stop()
	stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled reload reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("reload worker leaked")
	}
}

func TestPreviewCannotApplyAgainstOlderControlServer(t *testing.T) {
	dir := controlDirectory(t)
	path := filepath.Join(dir, "config.json")
	listener, err := net.Listen("unix", controlPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var applied atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reload" {
			applied.Add(1)
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.NotFound(w, r)
		}
	})}
	defer server.Close()
	go server.Serve(listener)
	if _, err := PreviewReload(t.Context(), dir, path); err == nil || applied.Load() != 0 {
		t.Fatal("old daemon applied preview", err)
	}
}

func TestReloadRejectsWrongConfigurationAndMalformedPreview(t *testing.T) {
	dir := controlDirectory(t)
	path := filepath.Join(dir, "config.json")
	var calls atomic.Int32
	stop, err := startReloadControl(dir, path, func(context.Context, bool) (ReloadPlan, error) {
		calls.Add(1)
		return ReloadPlan{Changes: []string{}}, nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	wrong := filepath.Join(dir, "other.json")
	if err := Reload(t.Context(), dir, wrong); err == nil || calls.Load() != 0 {
		t.Fatal("wrong config applied", err)
	}
	if _, err := PreviewReload(t.Context(), dir, wrong); err == nil || calls.Load() != 0 {
		t.Fatal("wrong config previewed", err)
	}
	if _, err := PreviewReload(t.Context(), dir, path); err != nil || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
	stop()
	for _, body := range []string{`{}`, `{"changes":[],"requires_restart":false} {}`, `{"changes":null,"requires_restart":false}`, `{"changes":[],"requires_restart":true}`} {
		listener, err := net.Listen("unix", controlPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })}
		go server.Serve(listener)
		_, err = PreviewReload(t.Context(), dir, path)
		server.Close()
		if err == nil {
			t.Fatal("malformed preview accepted", body)
		}
	}
}

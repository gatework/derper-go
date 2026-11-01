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
	entered := make(chan struct{})
	stop, err := startReloadControl(dir, func(ctx context.Context, _ bool) (ReloadPlan, error) {
		close(entered)
		<-ctx.Done()
		return ReloadPlan{}, ctx.Err()
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	done := make(chan error, 1)
	go func() { done <- Reload(t.Context(), dir) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reload did not start")
	}
	if err := Reload(t.Context(), dir); err == nil {
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
	if _, err := PreviewReload(t.Context(), dir); err == nil || applied.Load() != 0 {
		t.Fatal("old daemon applied preview", err)
	}
}

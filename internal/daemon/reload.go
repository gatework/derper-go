package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gatework/derper-go/internal/admission"
	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/relay"
)

type certificateSnapshot struct{ get relay.CertificateSource }
type liveCertificate struct {
	current atomic.Pointer[certificateSnapshot]
}

func (c *liveCertificate) set(get relay.CertificateSource) {
	c.current.Store(&certificateSnapshot{get})
}

func reloadConfiguration(path string, current *config.Settings, server *relay.Server, controller *admission.Controller, cert *liveCertificate) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	next, err := c.Resolve(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err = config.CheckReload(*current, next); err != nil {
		return err
	}
	var get relay.CertificateSource
	if !next.AutomaticCertificate() {
		get, err = certificate.Manual(next.Domain, next.CertificateFile, next.CertificateKey)
		if err != nil {
			return err
		}
	}
	// All fallible preparation is complete. In-flight checks and TLS handshakes
	// keep their original snapshots; established relay connections stay open.
	if controller != nil {
		controller.UpdatePolicy(next.AdmissionURL, next.AdmissionFailOpen, next.AdmissionTimeout)
	}
	server.UpdatePolicy(relay.Policy{Homepage: next.Homepage, AdmissionTimeout: next.AdmissionTimeout}, next.MaxConnections, next.ConnectionRate, next.ConnectionBurst)
	if get != nil {
		cert.set(get)
	}
	*current = next
	return nil
}

func controlPath(dir string) string {
	return filepath.Join(filepath.Dir(statusPath(dir)), "control.sock")
}

// startReloadControl is local-only: the private directory and 0600 Unix socket
// permit only the service account and root. No control endpoint is exposed on TLS.
func startReloadControl(dir string, reload func() error, logger *slog.Logger, signals <-chan os.Signal) (func(), error) {
	path := controlPath(dir)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("重载控制路径不是 Unix socket")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	var mu sync.Mutex
	apply := func() error {
		mu.Lock()
		defer mu.Unlock()
		if err := reload(); err != nil {
			logger.Warn("配置重载失败，保留原运行配置", "error", err)
			return err
		}
		logger.Info("配置已重载，现有中继连接保持运行")
		return nil
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/reload" {
			http.NotFound(w, r)
			return
		}
		if err := apply(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	stop := make(chan struct{})
	var workers sync.WaitGroup
	workers.Go(func() { _ = server.Serve(listener) })
	workers.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-signals:
				_ = apply()
			}
		}
	})
	return func() {
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(ctx) != nil {
			_ = server.Close()
		}
		_ = listener.Close()
		workers.Wait()
	}, nil
}

// Reload waits for acknowledgement from the running daemon, including rejection
// reasons. A failed reload never reports success just because a signal was sent.
func Reload(ctx context.Context, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", controlPath(dir))
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/reload", nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return errors.New("无法连接运行中的中继；请确认服务支持 reload 且当前用户有权限")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return errors.New(string(body))
	}
	return nil
}

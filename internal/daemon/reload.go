package daemon

import (
	"bytes"
	"context"
	"encoding/json"
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
	"unicode/utf8"

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

type ReloadPlan struct {
	Changes         []string `json:"changes"`
	RequiresRestart bool     `json:"requires_restart"`
	Error           string   `json:"error,omitempty"`
}

func reloadConfiguration(ctx context.Context, path string, current *config.Settings, server *relay.Server, controller *admission.Controller, cert *liveCertificate, preview bool) (ReloadPlan, error) {
	plan := ReloadPlan{Changes: []string{}}
	if err := ctx.Err(); err != nil {
		return plan, err
	}
	c, err := config.Load(path)
	if err != nil {
		return plan, err
	}
	next, err := c.Resolve(filepath.Dir(path))
	if err != nil {
		return plan, err
	}
	plan.Changes = config.ChangedFields(*current, next)
	if err = config.CheckReload(*current, next); err != nil {
		plan.RequiresRestart = true
		return plan, err
	}
	var get relay.CertificateSource
	if !next.AutomaticCertificate() {
		get, err = certificate.Manual(next.Domain, next.CertificateFile, next.CertificateKey)
		if err != nil {
			return plan, err
		}
	}
	if err := ctx.Err(); err != nil {
		return plan, err
	}
	if preview {
		return plan, nil
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
	return plan, nil
}

func controlPath(dir string) string {
	return filepath.Join(filepath.Dir(statusPath(dir)), "control.sock")
}

// startReloadControl is local-only: the private directory and 0600 Unix socket
// permit only the service account and root. No control endpoint is exposed on TLS.
func startReloadControl(dir, configPath string, reload func(context.Context, bool) (ReloadPlan, error), logger *slog.Logger, signals <-chan os.Signal) (func(), error) {
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var jobs sync.WaitGroup
	closing := false
	slot := make(chan struct{}, 1)
	busy := errors.New("另一配置重载正在执行，请稍后重试")
	apply := func(request context.Context, preview bool) (ReloadPlan, error) {
		mu.Lock()
		if closing || request.Err() != nil {
			mu.Unlock()
			return ReloadPlan{}, context.Canceled
		}
		select {
		case slot <- struct{}{}:
		default:
			mu.Unlock()
			return ReloadPlan{}, busy
		}
		jobs.Add(1)
		mu.Unlock()
		defer jobs.Done()
		defer func() { <-slot }()
		plan, err := reload(request, preview)
		if err != nil {
			logger.Warn("配置重载失败，保留原运行配置", "error", err)
			return plan, err
		}
		if !preview {
			logger.Info("配置已重载，现有中继连接保持运行")
		}
		return plan, nil
	}
	server := &http.Server{BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/config/reload" && r.URL.Path != "/config/reload/plan" {
			http.NotFound(w, r)
			return
		}
		preview := r.URL.Path == "/config/reload/plan"
		plan := ReloadPlan{Changes: []string{}}
		var input struct {
			ConfigPath string `json:"config_path"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&input)
		var extra any
		if err != nil || decoder.Decode(&extra) != io.EOF || input.ConfigPath == "" {
			err = errors.New("重载请求格式无效")
		} else if input.ConfigPath != configPath {
			err = errors.New("配置路径与此控制 socket 绑定的配置不同；请核对 --config 和 --state-dir")
		} else {
			plan, err = apply(r.Context(), preview)
		}
		if errors.Is(err, busy) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if preview {
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				plan.Error = err.Error()
				w.WriteHeader(http.StatusBadRequest)
			}
			_ = json.NewEncoder(w).Encode(plan)
			return
		}
		if err != nil {
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
			case _, ok := <-signals:
				if !ok {
					signals = nil
					continue
				}
				_, _ = apply(ctx, false)
			}
		}
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			closing = true
			mu.Unlock()
			cancel()
			close(stop)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(ctx) != nil {
				_ = server.Close()
			}
			_ = listener.Close()
			workers.Wait()
			jobs.Wait()
		})
	}, nil
}

// Reload waits for acknowledgement from the running daemon, including rejection
// reasons. A failed reload never reports success just because a signal was sent.
func Reload(ctx context.Context, dir, configPath string) error {
	_, err := reloadRequest(ctx, dir, configPath, false)
	return err
}

func PreviewReload(ctx context.Context, dir, configPath string) (ReloadPlan, error) {
	return reloadRequest(ctx, dir, configPath, true)
}

func reloadRequest(ctx context.Context, dir, configPath string, preview bool) (ReloadPlan, error) {
	var plan ReloadPlan
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", controlPath(dir))
	}}
	defer transport.CloseIdleConnections()
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return plan, err
	}
	body, err := json.Marshal(struct {
		ConfigPath string `json:"config_path"`
	}{configPath})
	if err != nil {
		return plan, err
	}
	endpoint := "http://localhost/config/reload"
	if preview {
		endpoint += "/plan"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return plan, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return plan, ctx.Err()
		}
		return plan, errors.New("无法连接运行中的中继；请确认服务支持 reload 且当前用户有权限")
	}
	defer response.Body.Close()
	if preview && (response.StatusCode == http.StatusOK || response.StatusCode == http.StatusBadRequest) {
		body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
		var wire struct {
			Changes         *[]string `json:"changes"`
			RequiresRestart *bool     `json:"requires_restart"`
			Error           string    `json:"error"`
		}
		if err != nil || len(body) > 16<<10 || !utf8.Valid(body) || json.Unmarshal(body, &wire) != nil || wire.Changes == nil || wire.RequiresRestart == nil || response.StatusCode == http.StatusBadRequest && wire.Error == "" || response.StatusCode == http.StatusOK && (wire.Error != "" || *wire.RequiresRestart) {
			return plan, errors.New("配置预览响应无效")
		}
		plan = ReloadPlan{Changes: *wire.Changes, RequiresRestart: *wire.RequiresRestart, Error: wire.Error}
		if response.StatusCode != http.StatusOK {
			return plan, errors.New(plan.Error)
		}
		return plan, nil
	}
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return plan, errors.New(string(body))
	}
	if preview {
		return plan, errors.New("当前服务不支持只读预览，请先升级")
	}
	return plan, nil
}

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gatework/derper-go/internal/admission"
	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/fileio"
	"github.com/gatework/derper-go/internal/relay"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/tailnet"
)

type Component struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}
type Status struct {
	Relay           Component             `json:"relay"`
	Mesh            Component             `json:"mesh"`
	Bootstrap       Component             `json:"bootstrap_dns"`
	AdmissionHealth Component             `json:"admission_health"`
	AdmissionMode   config.AdmissionMode  `json:"admission_mode"`
	Connections     relay.ConnectionStats `json:"connections"`
	Admission       admission.Stats       `json:"admission"`
	Domain          string                `json:"domain"`
	Phase           string                `json:"phase"`
	Cleanup         Component             `json:"certificate_cleanup"`
	PID             int                   `json:"pid"`
	Process         string                `json:"process"`
	Active          bool                  `json:"active"`
	Ready           bool                  `json:"ready"`
	Updated         time.Time             `json:"updated"`
	Certificate     Component             `json:"certificate"`
	DNS             Component             `json:"dns"`
	Tailnet         Component             `json:"tailnet"`
	Error           string                `json:"error,omitempty"`
}

func processIdentity(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return "", errors.New("进程标识无效")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return "", errors.New("进程标识不完整")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(boot)) + ":" + strconv.Itoa(pid) + ":" + fields[19], nil
}
func ReadStatus(dir string) (Status, error) {
	var s Status
	b, err := fileio.ReadRegularFile(statusPath(dir), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		b, err = fileio.ReadRegularFile(filepath.Join(dir, "status.json"), 1<<20) // v0.1.0
	}
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	inUse, err := state.InUse(dir)
	if err != nil {
		return s, err
	}
	identity, e := processIdentity(s.PID)
	s.Active = s.Active && inUse && e == nil && identity == s.Process
	if s.Active && time.Since(s.Updated) > 30*time.Second {
		s.Ready = false
		s.Phase = "stale"
		s.Error = "运行状态超过 30 秒未更新，请查看 service logs"
	}
	if !s.Active {
		if s.Relay.State != "disabled" {
			s.Relay.State = "stopped"
		}
		s.Phase = "stopped"
		s.Ready = false
	}
	return s, nil
}

// Custom foreground deployments keep disposable snapshots beside their state.
// The system service uses tmpfs, independently of durable identity and journals.
func statusPath(dir string) string {
	if filepath.Clean(dir) == config.DefaultDataDir {
		return filepath.Join(config.DefaultRuntimeDir, "status.json")
	}
	return filepath.Join(dir, "run", "status.json")
}

type health struct {
	controllerError func() error
	relayEnabled    bool
	mode            config.AdmissionMode
	mesh            func() relay.MeshStats
	connections     func() relay.ConnectionStats
	admission       func() admission.Stats
	logger          *slog.Logger
	mu              sync.Mutex
	path            string
	status          Status
	dirty           chan struct{}
	quit            chan struct{}
	done            chan struct{}
	stopOnce        sync.Once
	write           func(string, any) error
}

func newHealth(dir, domain string, logger *slog.Logger) (*health, error) {
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	h := &health{logger: logger, path: statusPath(dir), dirty: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{}), write: state.WriteSnapshot,
		status: Status{Domain: domain, PID: os.Getpid(), Process: identity, Active: true, Certificate: Component{State: "pending"}, DNS: Component{State: "pending"}, Tailnet: Component{State: "pending"}, Cleanup: Component{State: "pending"}}}
	if err = os.MkdirAll(filepath.Dir(h.path), 0700); err != nil {
		return nil, err
	}
	if err = h.save(); err != nil {
		return nil, err
	}
	go h.publish()
	return h, nil
}

func (h *health) snapshot() Status {
	h.mu.Lock()
	s := h.status
	connections, admission := h.connections, h.admission
	h.mu.Unlock()
	if connections != nil {
		s.Connections = connections()
	}
	if admission != nil {
		s.Admission = admission()
	}
	s.Updated = time.Now().UTC()
	switch {
	case !s.Active:
		s.Phase = "stopped"
	case !s.Ready:
		s.Phase = "starting"
	case s.Mesh.State == "degraded" || s.Bootstrap.State == "degraded" || s.AdmissionHealth.State == "degraded" || s.Certificate.State == "degraded" || s.DNS.State == "degraded" || s.Tailnet.State == "degraded" || s.Cleanup.State == "degraded":
		s.Phase = "degraded"
	default:
		s.Phase = "ready"
	}
	return s
}

func (h *health) save() error {
	// Only the publisher writes after startup. No filesystem I/O holds mu.
	err := h.write(h.path, h.snapshot())
	if err != nil {
		h.logger.Warn("无法保存运行状态，将在下次心跳重试", "error", err)
	}
	return err
}
func (h *health) changed() {
	select {
	case h.dirty <- struct{}{}:
	default:
	}
}
func (h *health) publish() {
	defer close(h.done)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.quit:
			_ = h.save()
			return
		case <-ticker.C:
		case <-h.dirty:
		}
		_ = h.save()
	}
}
func (h *health) ready(get relay.CertificateSource) error {
	pair, err := get(nil)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.status.Ready = true
	if h.status.Relay.State != "disabled" {
		h.status.Relay.State = "ready"
	}
	h.status.Certificate = Component{State: "ready", Detail: pair.Leaf.NotAfter.UTC().Format(time.RFC3339)}
	h.mu.Unlock()
	h.changed()
	return nil
}
func (h *health) stop(err error) {
	h.stopOnce.Do(func() {
		h.mu.Lock()
		h.status.Active, h.status.Ready = false, false
		if h.status.Relay.State != "disabled" {
			h.status.Relay.State = "stopped"
		}
		if err != nil {
			h.status.Error = err.Error()
		}
		h.mu.Unlock()
		close(h.quit)
		<-h.done
	})
}
func (h *health) dns(err error) {
	h.mu.Lock()
	h.status.DNS = Component{State: "ready"}
	if err != nil {
		h.status.DNS = Component{State: "degraded", Detail: err.Error()}
	}
	h.mu.Unlock()
	h.changed()
}
func (h *health) dnsDisabled() {
	h.mu.Lock()
	h.status.DNS = Component{State: "disabled"}
	h.mu.Unlock()
	h.changed()
}
func (h *health) monitor(ctx context.Context, get relay.CertificateSource, verifier *tailnet.Verifier, renewer *certificate.Renewer) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		check := Component{State: "public"}
		if h.mode == config.Controller || !h.relayEnabled {
			check.State = "disabled"
		}
		if verifier != nil {
			check.State = "ready"
			if err := verifier.Check(ctx); err != nil {
				check = Component{State: "degraded", Detail: err.Error()}
			}
		}
		pair, err := get(nil)
		var meshStats relay.MeshStats
		if h.mesh != nil {
			meshStats = h.mesh()
		}
		h.mu.Lock()
		h.status.Tailnet = check
		h.status.AdmissionHealth = check
		if h.relayEnabled && h.mode == config.Controller {
			h.status.AdmissionHealth = Component{State: "configured"}
			if h.admission != nil && h.admission().Checked > 0 {
				h.status.AdmissionHealth.State = "ready"
			}
			if h.controllerError != nil {
				if err := h.controllerError(); err != nil {
					h.status.AdmissionHealth = Component{State: "degraded", Detail: err.Error()}
				}
			}
		}
		if h.mesh != nil {
			stats := meshStats
			h.status.Mesh = Component{State: "ready", Detail: fmt.Sprintf("%d/%d 节点已连接", stats.Connected, stats.Peers-stats.Ignored)}
			if stats.Ignored > 0 {
				h.status.Mesh.Detail += fmt.Sprintf("（忽略 %d 个本机项）", stats.Ignored)
			}
			if stats.Connected < stats.Peers-stats.Ignored {
				h.status.Mesh.State = "degraded"
			}
		}
		h.status.Ready = err == nil
		if err != nil {
			h.status.Certificate = Component{State: "degraded", Detail: err.Error()}
		} else {
			h.status.Certificate = Component{State: "ready", Detail: pair.Leaf.NotAfter.UTC().Format(time.RFC3339)}
		}
		h.status.Cleanup = Component{State: "disabled"}
		if renewer != nil {
			h.status.Cleanup.State = "ready"
			if cleanupErr := renewer.CleanupError(); cleanupErr != nil {
				h.status.Cleanup = Component{State: "degraded", Detail: cleanupErr.Error()}
			}
			if renewalErr := renewer.RenewalError(); err == nil && renewalErr != nil {
				h.status.Certificate = Component{State: "degraded", Detail: "当前证书有效，续期检查失败：" + renewalErr.Error()}
			}
		}
		h.mu.Unlock()
		h.changed()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (h *health) watch(server *relay.Server, verifier *tailnet.Verifier, controller *admission.Controller, s config.Settings) {
	h.mu.Lock()
	h.mode = s.Access
	h.relayEnabled = s.RelayEnabled
	h.status.AdmissionMode = s.Access
	h.status.Relay = Component{State: "pending"}
	if !s.RelayEnabled {
		h.status.Relay.State = "disabled"
	}
	h.status.Mesh = Component{State: "disabled"}
	h.status.Bootstrap = Component{State: "disabled"}
	if len(s.BootstrapNames)+len(s.BootstrapUnlisted) > 0 {
		h.status.Bootstrap.State = "pending"
	}
	if len(s.MeshPeers) > 0 {
		h.mesh = server.Mesh
		h.status.Mesh.State = "pending"
	}
	h.connections = server.Connections
	if verifier != nil {
		h.admission = verifier.Stats
	}
	if controller != nil {
		h.controllerError = controller.Error
		h.admission = controller.Stats
	}
	h.mu.Unlock()
	h.changed()
}
func (h *health) bootstrap(err error) {
	h.mu.Lock()
	h.status.Bootstrap = Component{State: "ready"}
	if err != nil {
		h.status.Bootstrap = Component{State: "degraded", Detail: err.Error()}
	}
	h.mu.Unlock()
	h.changed()
}

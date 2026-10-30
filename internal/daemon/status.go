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

	"github.com/gatework/derper-go/internal/certificate"
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
	Domain      string    `json:"domain"`
	PID         int       `json:"pid"`
	Process     string    `json:"process"`
	Active      bool      `json:"active"`
	Ready       bool      `json:"ready"`
	Updated     time.Time `json:"updated"`
	Certificate Component `json:"certificate"`
	DNS         Component `json:"dns"`
	Tailnet     Component `json:"tailnet"`
	Error       string    `json:"error,omitempty"`
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
	b, err := fileio.ReadRegularFile(filepath.Join(dir, "status.json"), 1<<20)
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
		s.Error = "运行状态超过 30 秒未更新，请查看 service logs"
	}
	if !s.Active {
		s.Ready = false
	}
	return s, nil
}

type health struct {
	logger *slog.Logger
	mu     sync.Mutex
	dir    string
	status Status
}

func newHealth(dir, domain string) (*health, error) {
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		return nil, err
	}
	h := &health{logger: slog.Default(), dir: dir, status: Status{Domain: domain, PID: os.Getpid(), Process: identity, Active: true, Certificate: Component{State: "pending"}, DNS: Component{State: "pending"}, Tailnet: Component{State: "pending"}}}
	return h, h.save()
}
func (h *health) save() error {
	h.status.Updated = time.Now().UTC()
	err := state.WriteJSON(filepath.Join(h.dir, "status.json"), h.status)
	if err != nil {
		h.logger.Warn("无法保存运行状态", "error", err)
	}
	return err
}
func (h *health) ready(get relay.CertificateSource) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	pair, err := get(nil)
	if err != nil {
		return err
	}
	h.status.Ready = true
	h.status.Certificate = Component{State: "ready", Detail: pair.Leaf.NotAfter.UTC().Format(time.RFC3339)}
	return h.save()
}
func (h *health) stop(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.Active = false
	h.status.Ready = false
	if err != nil {
		h.status.Error = err.Error()
	}
	_ = h.save()
}
func (h *health) dns(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.DNS = Component{State: "ready"}
	if err != nil {
		h.status.DNS = Component{State: "degraded", Detail: err.Error()}
	}
	_ = h.save()
}
func (h *health) dnsDisabled() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.DNS = Component{State: "disabled"}
	_ = h.save()
}
func (h *health) monitor(ctx context.Context, get relay.CertificateSource, verifier *tailnet.Verifier, renewer *certificate.Renewer) {
	for {
		check := Component{State: "public"}
		if verifier != nil {
			check.State = "ready"
			if err := verifier.Check(ctx); err != nil {
				check = Component{State: "degraded", Detail: err.Error()}
			}
		}
		pair, err := get(nil)
		h.mu.Lock()
		h.status.Tailnet = check
		h.status.Ready = err == nil
		if err != nil {
			h.status.Certificate = Component{State: "degraded", Detail: err.Error()}
		} else {
			h.status.Certificate = Component{State: "ready", Detail: pair.Leaf.NotAfter.UTC().Format(time.RFC3339)}
		}
		if err == nil && renewer != nil {
			if renewalErr := renewer.RenewalError(); renewalErr != nil {
				h.status.Certificate.State = "degraded"
				h.status.Certificate.Detail = "当前证书有效，续期检查失败：" + renewalErr.Error()
			}
		}
		_ = h.save()
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

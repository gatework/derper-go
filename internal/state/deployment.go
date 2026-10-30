package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/fileio"
)

// Deployment records approved setup work, separate from editable user intent.
type Deployment struct {
	Config      json.RawMessage     `json:"config,omitempty"`
	Domain      string              `json:"domain"`
	ConfigHash  string              `json:"config_hash"`
	Phase       string              `json:"phase"`
	AcceptedCA  string              `json:"accepted_ca,omitempty"`
	AcceptedAt  time.Time           `json:"accepted_at,omitempty"`
	ApprovedDNS []cloudflare.Record `json:"approved_dns,omitempty"`
}

func ReadDeployment(dir string) (Deployment, error) {
	var d Deployment
	b, err := fileio.ReadRegularFile(filepath.Join(dir, "setup.json"), 1<<20)
	if err == nil {
		err = json.Unmarshal(b, &d)
	}
	return d, err
}
func SaveDeployment(dir string, d Deployment) error {
	return WriteJSON(filepath.Join(dir, "setup.json"), d)
}
func CheckTerms(dir, domain, ca string) error {
	d, err := ReadDeployment(dir)
	if err != nil || d.Domain != domain || d.AcceptedCA != ca || d.AcceptedAt.IsZero() {
		return errors.New("尚未确认此域名和证书机构的服务条款，请先执行 derper-go init")
	}
	return nil
}

// InUse checks an existing lock without creating state. A snapshot alone never
// proves that a process is alive after a crash or reboot.
func InUse(dir string) (bool, error) {
	f, err := os.OpenFile(filepath.Join(dir, "process.lock"), os.O_RDONLY|lockFlags, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("状态锁必须是普通文件")
	}
	return locked(f)
}

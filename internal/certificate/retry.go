package certificate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gatework/derper-go/internal/cloudflare"
	"golang.org/x/crypto/acme"
)

type retryWindow struct {
	Until time.Time `json:"until"`
}

func (r *retryWindow) Error() string {
	return "certificate issuance deferred until " + r.Until.UTC().Format(time.RFC3339)
}
func retryDelay(err error) time.Duration {
	var window *retryWindow
	if errors.As(err, &window) {
		return max(0, time.Until(window.Until))
	}
	var cf *cloudflare.Error
	if errors.As(err, &cf) {
		if cf.RetryAfter > 0 {
			return cf.RetryAfter
		}
		if cf.Status == 429 {
			return 5 * time.Minute
		}
	}
	var ca *acme.Error
	if errors.As(err, &ca) {
		if d := cloudflare.RetryAfter(ca.Header.Get("Retry-After")); d > 0 {
			return d
		}
		if ca.StatusCode == 429 {
			return time.Hour
		}
	}
	return 0
}
func (m *Renewer) checkRetry() error { return m.checkRetryFile("retry.json") }
func (m *Renewer) checkRetryFile(name string) error {
	b, err := readFile(filepath.Join(m.cachePath, name), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var w retryWindow
	if err = json.Unmarshal(b, &w); err != nil || w.Until.IsZero() {
		return errors.New("invalid certificate retry state")
	}
	if time.Now().Before(w.Until) {
		return &w
	}
	return nil
}
func (m *Renewer) rememberRetry(result error) error { return m.rememberRetryFile("retry.json", result) }
func (m *Renewer) rememberRetryFile(name string, result error) error {
	path := filepath.Join(m.cachePath, name)
	if result == nil {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	delay := retryDelay(result)
	if delay == 0 {
		return nil
	}
	b, err := json.Marshal(retryWindow{Until: time.Now().Add(delay).UTC()})
	if err != nil {
		return err
	}
	if err = atomicWrite(path, b); err != nil {
		return fmt.Errorf("persist certificate retry window: %w", err)
	}
	return nil
}

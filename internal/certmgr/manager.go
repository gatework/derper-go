package certmgr

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gatework/derper-go/internal/cloudflare"
)

const certificateCheckInterval = time.Hour

type managerState uint8

const (
	managerNew managerState = iota
	managerStarting
	managerRunning
	managerClosed
)

// Manager 由启动它的服务独占。Start 只能调用一次，Close 取消并等待所有维护任务。
type Manager struct {
	certificateMu sync.Mutex
	config        Config
	logger        *slog.Logger
	getenv        func(string) string
	http          *http.Client
	dns           *cloudflare.Client
	lookupTXT     func(context.Context, string) ([]string, error)
	current       atomic.Pointer[tls.Certificate]
	cachePath     string
	lock          *os.File
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closeOnce     sync.Once
	lifecycleMu   sync.Mutex
	state         managerState
	startDone     chan struct{}
}

// New 不进行 I/O，供 --check 与服务端配置校验复用。
func New(c Config, logger *slog.Logger, getenv func(string) string) (*Manager, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirects are not allowed") }}
	return &Manager{config: c.normalized(), logger: logger, getenv: getenv, http: client, lookupTXT: net.DefaultResolver.LookupTXT}, nil
}

func (m *Manager) token() (string, error) {
	var value string
	if m.config.Cloudflare.TokenFile != "" {
		b, err := readFile(m.config.Cloudflare.TokenFile, 8<<10)
		if err != nil {
			return "", fmt.Errorf("read cloudflare token file: %w", err)
		}
		value = string(b)
	} else {
		value = m.getenv(m.config.Cloudflare.TokenEnv)
	}
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\t ") {
		return "", fmt.Errorf("cloudflare API token is missing or invalid")
	}
	return value, nil
}

func (m *Manager) Start(parent context.Context) (err error) {
	m.lifecycleMu.Lock()
	if m.state != managerNew {
		m.lifecycleMu.Unlock()
		return fmt.Errorf("certificate manager Start requires a new instance")
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.state = managerStarting
	m.startDone = make(chan struct{})
	m.lifecycleMu.Unlock()
	defer func() {
		m.lifecycleMu.Lock()
		if err == nil && m.state == managerClosed {
			err = ctx.Err()
		}
		if err != nil {
			m.state = managerClosed
			cancel()
		} else {
			m.state = managerRunning
		}
		close(m.startDone)
		m.lifecycleMu.Unlock()
		if err != nil {
			m.Close()
		}
	}()
	m.dns = cloudflare.NewSource(m.token, m.config.Cloudflare.ZoneID, m.http)
	if err = m.openCache(); err != nil {
		return err
	}
	if err = m.loadCertificate(); err != nil {
		return err
	}
	// 有效缓存立即投入服务，控制平面操作全部转入后台。
	_, cachedErr := m.GetCertificate(nil)
	cached := cachedErr == nil
	if !cached {
		if err = m.renew(ctx); err != nil {
			return fmt.Errorf("initial ACME issuance: %w", err)
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	m.wg.Add(1)
	go m.maintainScheduled(ctx, certificateCheckInterval, "ACME renewal", m.maintainCertificate, cached, m.certificateCheckDelay)
	return nil
}

func (m *Manager) maintainCertificate(ctx context.Context) error {
	if m.renewDue(time.Now()) {
		return m.renew(ctx)
	}
	m.certificateMu.Lock()
	defer m.certificateMu.Unlock()
	return m.cleanupPending(ctx)
}

func (m *Manager) maintain(ctx context.Context, interval time.Duration, name string, action func(context.Context) error, initial bool) {
	m.maintainScheduled(ctx, interval, name, action, initial, nil)
}

// next 在成功后重新读取当前状态，不能沿用签发前的证书期限。
func (m *Manager) maintainScheduled(ctx context.Context, interval time.Duration, name string, action func(context.Context) error, initial bool, next func(time.Time) time.Duration) {
	defer m.wg.Done()
	// 维护成功按正常周期检查；短暂故障先快速恢复，再有界退避，避免等满一小时。
	firstRetry := min(30*time.Second, max(time.Nanosecond, interval/10))
	retry, delay := firstRetry, interval
	if next != nil {
		delay = min(interval, next(time.Now()))
	}
	if initial {
		delay = 0
	}
	for {
		if wait(ctx, delay) != nil || ctx.Err() != nil {
			return
		}
		dueBefore := next != nil && next(time.Now()) <= 0
		err := action(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			delay = retry
			delay = max(delay, retryDelay(err))
			retry = min(interval, 15*time.Minute, retry*2)
			m.logger.Warn(name+" failed; will retry", "error", err, "retry_in", delay)
		} else {
			delay, retry = interval, firstRetry
			if next != nil {
				delay = min(interval, next(time.Now()))
				// 仅已处理过到期状态才退避；维护期间刚跨过续期点应立即再检查。
				// CA 可能返回仍在续期窗口中的有效证书，不能零等待反复下单。
				if delay <= 0 && dueBefore {
					delay = m.certificateRetryDelay(time.Now(), firstRetry)
				}
			}
		}
	}
}

func (m *Manager) renewDue(now time.Time) bool {
	return m.certificateCheckDelay(now) == 0
}

// 正常检查不晚于续期点，最长一小时；已到期或尚未生效的证书立即处理。
func (m *Manager) certificateCheckDelay(now time.Time) time.Duration {
	cert := m.current.Load()
	if cert == nil || now.Before(cert.Leaf.NotBefore) {
		return 0
	}
	lifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	before := min(30*24*time.Hour, lifetime/3)
	return min(certificateCheckInterval, max(0, cert.Leaf.NotAfter.Add(-before).Sub(now)))
}

// 已到续期点的有效证书仍需留下下一次签发预算；过期或缺失时保留有界故障等待。
func (m *Manager) certificateRetryDelay(now time.Time, limit time.Duration) time.Duration {
	cert := m.current.Load()
	if cert != nil {
		if remaining := cert.Leaf.NotAfter.Sub(now); remaining > 0 {
			return min(limit, max(time.Nanosecond, remaining/2))
		}
	}
	return limit
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil && hello.ServerName != "" && !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), m.config.Domain) {
		return nil, fmt.Errorf("unconfigured TLS server name")
	}
	cert := m.current.Load()
	if cert == nil {
		return nil, fmt.Errorf("ACME certificate is not ready")
	}
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("ACME certificate is outside its validity period")
	}
	return cert, nil
}

func (m *Manager) Close() {
	m.lifecycleMu.Lock()
	m.state = managerClosed
	if m.cancel != nil {
		m.cancel()
	}
	done := m.startDone
	m.lifecycleMu.Unlock()
	if done != nil {
		<-done
	}
	m.closeOnce.Do(func() {
		m.wg.Wait()
		if m.lock != nil {
			_ = syscall.Flock(int(m.lock.Fd()), syscall.LOCK_UN)
			_ = m.lock.Close()
		}
	})
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

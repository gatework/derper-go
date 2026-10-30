package certificate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gatework/derper-go/internal/cloudflare"
)

const certificateCheckInterval = time.Hour

type renewerState uint8

const (
	renewerNew renewerState = iota
	renewerStarting
	renewerRunning
	renewerClosed
)

// Renewer 由启动它的服务独占。Start 只能调用一次，Close 取消并等待所有维护任务。
type renewalFailure struct{ err error }

type Renewer struct {
	failure atomic.Pointer[renewalFailure]
	*Store
	certificateMu sync.Mutex
	config        Options
	logger        *slog.Logger
	getenv        func(string) string
	http          *http.Client
	dns           *cloudflare.Client
	lookupTXT     func(context.Context, string) ([]string, error)
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closeOnce     sync.Once
	lifecycleMu   sync.Mutex
	state         renewerState
	startDone     chan struct{}
}

// New 不进行 I/O，供 --check 与服务端配置校验复用。
func New(c Options, logger *slog.Logger, getenv func(string) string) (*Renewer, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	client := cloudflare.HTTPClient()
	return &Renewer{Store: &Store{domain: c.normalized().Domain}, config: c.normalized(), logger: logger, getenv: getenv, http: client, lookupTXT: net.DefaultResolver.LookupTXT}, nil
}

func (m *Renewer) token() (string, error) {
	return (cloudflare.Credentials{File: m.config.Cloudflare.TokenFile, Environment: m.config.Cloudflare.TokenEnv}).ReadEnv(m.getenv)
}

func (m *Renewer) Start(parent context.Context) (err error) {
	m.lifecycleMu.Lock()
	if m.state != renewerNew {
		m.lifecycleMu.Unlock()
		return fmt.Errorf("证书续期器不能重复启动")
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.state = renewerStarting
	m.startDone = make(chan struct{})
	m.lifecycleMu.Unlock()
	defer func() {
		m.lifecycleMu.Lock()
		if err == nil && m.state == renewerClosed {
			err = ctx.Err()
		}
		if err != nil {
			m.state = renewerClosed
			cancel()
		} else {
			m.state = renewerRunning
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

func (m *Renewer) maintainCertificate(ctx context.Context) error {
	if m.renewDue(time.Now()) {
		return m.renew(ctx)
	}
	m.certificateMu.Lock()
	defer m.certificateMu.Unlock()
	return m.cleanupPending(ctx)
}

func (m *Renewer) maintain(ctx context.Context, interval time.Duration, name string, action func(context.Context) error, initial bool) {
	m.maintainScheduled(ctx, interval, name, action, initial, nil)
}

// next 在成功后重新读取当前状态，不能沿用签发前的证书期限。
func (m *Renewer) maintainScheduled(ctx context.Context, interval time.Duration, name string, action func(context.Context) error, initial bool, next func(time.Time) time.Duration) {
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
		if err != nil {
			m.failure.Store(&renewalFailure{err})
		} else {
			m.failure.Store(nil)
		}
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

func (m *Renewer) renewDue(now time.Time) bool {
	return m.certificateCheckDelay(now) == 0
}

// 正常检查不晚于续期点，最长一小时；已到期或尚未生效的证书立即处理。
func (m *Renewer) certificateCheckDelay(now time.Time) time.Duration {
	cert := m.current.Load()
	if cert == nil || now.Before(cert.Leaf.NotBefore) {
		return 0
	}
	lifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	before := min(30*24*time.Hour, lifetime/3)
	return min(certificateCheckInterval, max(0, cert.Leaf.NotAfter.Add(-before).Sub(now)))
}

// 已到续期点的有效证书仍需留下下一次签发预算；过期或缺失时保留有界故障等待。
func (m *Renewer) certificateRetryDelay(now time.Time, limit time.Duration) time.Duration {
	cert := m.current.Load()
	if cert != nil {
		if remaining := cert.Leaf.NotAfter.Sub(now); remaining > 0 {
			return min(limit, max(time.Nanosecond, remaining/2))
		}
	}
	return limit
}

func (m *Renewer) Close() {
	m.lifecycleMu.Lock()
	m.state = renewerClosed
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

// RenewalError reports the last maintenance failure without invalidating a
// still-valid TLS snapshot. A later successful attempt clears it.
func (m *Renewer) RenewalError() error {
	if failure := m.failure.Load(); failure != nil {
		return failure.err
	}
	return nil
}

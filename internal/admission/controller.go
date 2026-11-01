// Package admission provides bounded access to an external DERP admission controller.
package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/tailcfg"
)

var (
	ErrDenied      = errors.New("准入控制器拒绝连接")
	ErrUnavailable = errors.New("准入控制服务不可用")
	ErrLimit       = errors.New("已达到准入请求上限")
	ErrClosed      = errors.New("准入控制器已关闭")
)

type Stats struct {
	PeakRunning         int64  `json:"peak_running"`
	Checked             uint64 `json:"checked"`
	FailOpen            uint64 `json:"fail_open"`
	Requests            int    `json:"requests"`
	Running             int    `json:"running"`
	MaxConcurrentChecks int    `json:"max_concurrent_checks"`
	MaxRequests         int    `json:"max_requests"`
	Rejected            uint64 `json:"rejected"`
	Limited             uint64 `json:"limited"`
	Coalesced           uint64 `json:"coalesced"`
}
type Options struct {
	URL                 string
	FailOpen            bool
	Timeout             time.Duration
	MaxConcurrentChecks int
	MaxRequests         int
}
type controllerFailure struct{ err error }
type Controller struct {
	running, peak     atomic.Int64
	failure           atomic.Pointer[controllerFailure]
	checked, failOpen atomic.Uint64
	policy            atomic.Pointer[Options]
	client            *http.Client
	transport         *http.Transport
	ctx               context.Context
	cancel            context.CancelFunc
	mu                sync.Mutex
	closed            bool
	wg                sync.WaitGroup
	requests, checks  chan struct{}
	rejected, limited atomic.Uint64
}

func New(options Options) *Controller {
	if options.Timeout == 0 {
		options.Timeout = 3 * time.Second
	}
	if options.MaxConcurrentChecks <= 0 {
		options.MaxConcurrentChecks = 32
	}
	if options.MaxRequests <= 0 {
		options.MaxRequests = 128
	}
	options.MaxRequests = min(options.MaxRequests, 8192)
	options.MaxConcurrentChecks = min(options.MaxConcurrentChecks, 128, options.MaxRequests)
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, ExpectContinueTimeout: time.Second}
	transport.DialContext = (&net.Dialer{Timeout: time.Second}).DialContext
	transport.ResponseHeaderTimeout = 3 * time.Second
	transport.TLSHandshakeTimeout = 3 * time.Second
	transport.MaxIdleConns, transport.MaxIdleConnsPerHost, transport.MaxConnsPerHost = options.MaxConcurrentChecks, options.MaxConcurrentChecks, options.MaxConcurrentChecks
	transport.IdleConnTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	controller := &Controller{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport: transport, ctx: ctx, cancel: cancel, requests: make(chan struct{}, options.MaxRequests), checks: make(chan struct{}, options.MaxConcurrentChecks)}
	controller.policy.Store(&options)
	return controller
}

// UpdatePolicy affects new checks; in-flight checks keep their original snapshot.
func (c *Controller) UpdatePolicy(url string, failOpen bool, timeout time.Duration) {
	options := *c.policy.Load()
	options.URL, options.FailOpen, options.Timeout = url, failOpen, timeout
	c.policy.Store(&options)
}
func (c *Controller) Stats() Stats {
	return Stats{PeakRunning: c.peak.Load(), Checked: c.checked.Load(), FailOpen: c.failOpen.Load(), Requests: len(c.requests), Running: len(c.checks), MaxConcurrentChecks: cap(c.checks), MaxRequests: cap(c.requests), Rejected: c.rejected.Load(), Limited: c.limited.Load()}
}
func (c *Controller) Close() {
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.wg.Wait()
	c.transport.CloseIdleConnections()
}
func (c *Controller) VerifyClient(parent context.Context, request tailcfg.DERPAdmitClientRequest) (err error) {
	defer func() {
		if err != nil {
			c.rejected.Add(1)
		}
	}()
	if err = parent.Err(); err != nil {
		return err
	}
	if request.NodePublic.IsZero() {
		return ErrDenied
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()
	select {
	case c.requests <- struct{}{}:
		defer func() { <-c.requests }()
	default:
		c.limited.Add(1)
		return ErrLimit
	}
	options := c.policy.Load()
	ctx, cancel := context.WithTimeout(parent, options.Timeout)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	if c.ctx.Err() != nil {
		return ErrClosed
	}
	select {
	case c.checks <- struct{}{}:
		defer func() { <-c.checks }()
	case <-ctx.Done():
		return ctx.Err()
	}
	n := c.running.Add(1)
	for old := c.peak.Load(); n > old && !c.peak.CompareAndSwap(old, n); old = c.peak.Load() {
	}
	defer c.running.Add(-1)
	c.checked.Add(1)
	err = c.query(ctx, request, options)
	if c.ctx.Err() != nil {
		return ErrClosed
	}
	if errors.Is(parent.Err(), context.Canceled) {
		return parent.Err()
	}
	if errors.Is(err, ErrUnavailable) {
		c.failure.Store(&controllerFailure{err})
	} else {
		c.failure.Store(nil)
	}
	if parent.Err() != nil && !(options.FailOpen && errors.Is(err, ErrUnavailable)) {
		return parent.Err()
	}
	// Only a controller outage can use the explicitly configured fallback.
	if options.FailOpen && errors.Is(err, ErrUnavailable) {
		c.failOpen.Add(1)
		return nil
	}
	return err
}
func (c *Controller) query(ctx context.Context, request tailcfg.DERPAdmitClientRequest, options *Options) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, options.URL, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		var wrapped *url.Error
		if errors.As(err, &wrapped) {
			err = wrapped.Err
		} // do not expose a URL query in diagnostics
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w (HTTP %d)", ErrUnavailable, response.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return fmt.Errorf("%w: response read failed", ErrUnavailable)
	}
	if len(body) > 4096 {
		return fmt.Errorf("%w: response exceeds 4 KiB", ErrUnavailable)
	}
	var result struct{ Allow *bool }
	if json.Unmarshal(body, &result) != nil || result.Allow == nil {
		return fmt.Errorf("%w: invalid response", ErrUnavailable)
	}
	if !*result.Allow {
		return ErrDenied
	}
	return nil
}

func (c *Controller) Error() error {
	if failure := c.failure.Load(); failure != nil {
		return failure.err
	}
	return nil
}

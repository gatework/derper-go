// Package tailnet queries the existing tailscaled; it never manages its lifecycle.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	DefaultMaxConcurrentChecks = 32
	maxAdmissionRequests       = 128
	admissionTimeout           = 3 * time.Second
)

var (
	ErrClosed         = errors.New("Tailnet 验证器已关闭")
	ErrAdmissionLimit = errors.New("Tailnet 准入请求已达上限")
	ErrUnauthorized   = errors.New("节点未获 Tailnet 授权")
)

type Options struct {
	Socket              string
	MaxConcurrentChecks int
}
type AdmissionStats struct {
	Requests            int    `json:"requests"`
	Running             int    `json:"running"`
	MaxConcurrentChecks int    `json:"max_concurrent_checks"`
	MaxRequests         int    `json:"max_requests"`
	Rejected            uint64 `json:"rejected"`
	Limited             uint64 `json:"limited"`
	Coalesced           uint64 `json:"coalesced"`
}
type nodeCheck struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	err     error
}
type Verifier struct {
	client                       *local.Client
	transport                    *http.Transport
	ctx                          context.Context
	cancel                       context.CancelFunc
	mu                           sync.Mutex
	closed                       bool
	calls                        map[key.NodePublic]*nodeCheck
	requests                     chan struct{}
	checks                       chan struct{}
	wg                           sync.WaitGroup
	rejected, limited, coalesced atomic.Uint64
	lookup                       func(context.Context, key.NodePublic) error
}

func New(options Options) *Verifier {
	limit := options.MaxConcurrentChecks
	if limit <= 0 {
		limit = DefaultMaxConcurrentChecks
	}
	limit = min(limit, maxAdmissionRequests)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", options.Socket)
	}, ResponseHeaderTimeout: admissionTimeout, MaxIdleConns: limit + 2, MaxIdleConnsPerHost: limit + 2, MaxConnsPerHost: limit + 2, IdleConnTimeout: time.Minute}
	ctx, cancel := context.WithCancel(context.Background())
	v := &Verifier{client: &local.Client{Socket: options.Socket, UseSocketOnly: true, Transport: transport}, transport: transport, ctx: ctx, cancel: cancel, calls: make(map[key.NodePublic]*nodeCheck), requests: make(chan struct{}, maxAdmissionRequests), checks: make(chan struct{}, limit)}
	v.lookup = v.lookupNode
	return v
}
func (v *Verifier) Close() {
	v.mu.Lock()
	v.closed = true
	v.cancel()
	v.mu.Unlock()
	v.wg.Wait()
	v.transport.CloseIdleConnections()
}
func (v *Verifier) Stats() AdmissionStats {
	return AdmissionStats{Requests: len(v.requests), Running: len(v.checks), MaxConcurrentChecks: cap(v.checks), MaxRequests: cap(v.requests), Rejected: v.rejected.Load(), Limited: v.limited.Load(), Coalesced: v.coalesced.Load()}
}
func (v *Verifier) VerifyNode(parent context.Context, node key.NodePublic) (err error) {
	defer func() {
		if err != nil {
			v.rejected.Add(1)
		}
	}()
	if err = parent.Err(); err != nil {
		return err
	}
	if node.IsZero() {
		return ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(parent, admissionTimeout)
	defer cancel()
	select {
	case v.requests <- struct{}{}:
		defer func() { <-v.requests }()
	default:
		v.limited.Add(1)
		return ErrAdmissionLimit
	}
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return ErrClosed
	}
	call := v.calls[node]
	if call == nil {
		// A shared lookup has its own service-owned deadline. One caller's
		// cancellation must not revoke another caller's in-flight result.
		checkCtx, stop := context.WithTimeout(v.ctx, admissionTimeout)
		call = &nodeCheck{done: make(chan struct{}), cancel: stop}
		v.calls[node] = call
		v.wg.Add(1) // serialized with Close, including the first Add
		go v.checkNode(checkCtx, node, call)
	} else {
		v.coalesced.Add(1)
	}
	call.waiters++
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		call.waiters--
		if call.waiters == 0 {
			call.cancel()
			if v.calls[node] == call {
				delete(v.calls, node)
			}
		}
		v.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-v.ctx.Done():
		return ErrClosed
	case <-call.done:
		// Prefer cancellation to a simultaneously completed authorization.
		if err := ctx.Err(); err != nil {
			return err
		}
		if v.ctx.Err() != nil {
			return ErrClosed
		}
		return call.err
	}
}
func (v *Verifier) checkNode(ctx context.Context, node key.NodePublic, call *nodeCheck) {
	defer v.wg.Done()
	defer call.cancel()
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case v.checks <- struct{}{}:
		if err = ctx.Err(); err == nil {
			err = v.lookup(ctx, node)
		}
		<-v.checks
	}
	v.mu.Lock()
	call.err = err
	if v.calls[node] == call {
		delete(v.calls, node)
	} // never cache a completed decision
	close(call.done)
	v.mu.Unlock()
}
func (v *Verifier) lookupNode(ctx context.Context, node key.NodePublic) error {
	who, err := v.client.WhoIsNodeKey(ctx, node)
	if err != nil {
		return fmt.Errorf("无法查询 Tailnet 节点：%w", err)
	}
	if who == nil || who.Node == nil {
		return ErrUnauthorized
	}
	return nil
}

// withTimeout binds health/discovery requests to both caller and service lifetime.
func (v *Verifier) withTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	stop := context.AfterFunc(v.ctx, cancel)
	if v.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}
func (v *Verifier) Check(ctx context.Context) error {
	ctx, cancel := v.withTimeout(ctx)
	defer cancel()
	status, err := v.client.StatusWithoutPeers(ctx)
	if err != nil {
		return fmt.Errorf("无法连接 tailscaled；请先安装并启动 Tailscale：%w", err)
	}
	if status.BackendState != "Running" {
		return fmt.Errorf("tailscaled 尚未就绪（%s）；请执行 sudo tailscale up 完成登录", status.BackendState)
	}
	return nil
}

// Region selects a free custom region during setup. Runtime uses the saved value.
func (v *Verifier) Region(ctx context.Context, requested int) (int, error) {
	ctx, cancel := v.withTimeout(ctx)
	defer cancel()
	m, err := v.client.CurrentDERPMap(ctx)
	if err != nil {
		return 0, fmt.Errorf("读取 Tailnet 中继区域：%w", err)
	}
	if m == nil {
		return 0, errors.New("tailscaled 尚无中继地图，请等待登录完成")
	}
	if requested != 0 {
		if m.Regions[tailcfg.DERPRegionID(requested)] != nil {
			return 0, fmt.Errorf("中继区域 %d 已被占用", requested)
		}
		return requested, nil
	}
	for id := 900; id <= 999; id++ {
		if m.Regions[tailcfg.DERPRegionID(id)] == nil {
			return id, nil
		}
	}
	return 0, errors.New("900–999 区域编号均已被占用，请先整理 Tailnet 中继配置")
}

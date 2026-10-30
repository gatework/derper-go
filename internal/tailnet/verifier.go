// Package tailnet queries the existing tailscaled; it never manages its lifecycle.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type Verifier struct {
	client    *local.Client
	transport *http.Transport
}

func New(socket string) *Verifier {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}, ResponseHeaderTimeout: 3 * time.Second, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: time.Minute}
	return &Verifier{client: &local.Client{Socket: socket, UseSocketOnly: true, Transport: transport}, transport: transport}
}
func (v *Verifier) Close() { v.transport.CloseIdleConnections() }
func (v *Verifier) VerifyNode(ctx context.Context, node key.NodePublic) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	who, err := v.client.WhoIsNodeKey(ctx, node)
	if err != nil {
		return fmt.Errorf("无法查询 Tailnet 节点：%w", err)
	}
	if who == nil || who.Node == nil {
		return errors.New("节点未获 Tailnet 授权")
	}
	return nil
}
func (v *Verifier) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
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
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
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

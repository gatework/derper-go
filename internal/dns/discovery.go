package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gatework/derper-go/internal/config"
)

// DiscoverIPv4 uses IPv4 HTTPS connections with independent bounded fallbacks.
func DiscoverIPv4(ctx context.Context) (string, error) {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp4", address)
	}, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("公网地址查询不接受重定向") }}
	return discoverIPv4(ctx, client, []string{"https://api.ipify.org", "https://checkip.amazonaws.com"})
}
func discoverIPv4(ctx context.Context, client *http.Client, endpoints []string) (string, error) {
	var failures []error
	for _, endpoint := range endpoints {
		value, err := queryIPv4(ctx, client, endpoint)
		if err == nil {
			return value, nil
		}
		failures = append(failures, err)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "", fmt.Errorf("公网 IPv4 发现失败，已保留已发布记录；可手动指定 dns.ipv4：%w", errors.Join(failures...))
}
func queryIPv4(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", errors.New("地址查询连接失败")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("地址查询 HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 65))
	if err != nil || len(b) > 64 {
		return "", errors.New("地址查询响应无效")
	}
	ip, err := config.Address(string(b), true)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/tailnet"
	"tailscale.com/net/stun"
)

type CheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Doctor only queries services. TLS/STUN reachability is not a claim of authorized DERP forwarding.
func Doctor(ctx context.Context, c config.Settings) []CheckResult {
	var out []CheckResult
	add := func(name, detail string, err error) {
		if err != nil {
			detail = err.Error()
		}
		out = append(out, CheckResult{name, err == nil, detail})
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, c.Domain)
	if err == nil {
		err = checkAddresses(c, ips)
	}
	if err != nil {
		err = fmt.Errorf("%w；核对 DNS 传播、Cloudflare DNS-only 以及代理出口，固定地址应使用 dns.ipv4/dns.ipv6", err)
	}
	add("DNS", fmt.Sprint(ips), err)
	port := strconv.Itoa(c.Port)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: c.Domain, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(c.Domain, port))
	detail := ""
	if err == nil {
		tlsConn := conn.(*tls.Conn)
		detail = tlsConn.ConnectionState().PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
		conn.Close()
	}
	if err != nil {
		err = fmt.Errorf("%w；检查 HTTPS 监听、安全组及代理回包路由", err)
	}
	add("TLS", detail, err)
	if c.STUNEnabled {
		p := strconv.Itoa(c.STUNPort)
		err = checkSTUN(ctx, net.JoinHostPort(c.Domain, p))
		if err != nil {
			err = fmt.Errorf("%w；检查 UDP 端口、安全组及代理回包路由", err)
		}
		add("STUN", "STUN 地址绑定响应有效", err)
	}
	if c.RelayEnabled && c.Access == config.Tailnet {
		verifier := tailnet.New(tailnet.Options{Socket: c.Socket, MaxConcurrentChecks: c.MaxConcurrentChecks})
		err := verifier.Check(ctx)
		verifier.Close()
		add("Tailnet", "tailscaled 已就绪；实际转发需用两台已授权设备验证", err)

	}
	return out
}

func checkAddresses(c config.Settings, ips []net.IPAddr) error {
	if len(ips) == 0 {
		return errors.New("域名尚未解析到地址")
	}
	addresses := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.IP); ok {
			addresses = append(addresses, a.Unmap())
		}
	}
	for _, want := range []netip.Addr{c.IPv4, c.IPv6} {
		if want.IsValid() && !slices.Contains(addresses, want) {
			return fmt.Errorf("解析结果 %v 未包含配置的固定地址 %s", addresses, want)
		}
	}
	return nil
}

func checkSTUN(ctx context.Context, address string) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	tx := stun.NewTxID()
	if _, err = conn.Write(stun.Request(tx)); err != nil {
		return err
	}
	var buf [2048]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		return err
	}
	got, addr, err := stun.ParseResponse(buf[:n])
	if err != nil {
		return err
	}
	if got != tx || !addr.IsValid() {
		return errors.New("STUN returned invalid transaction or mapped address")
	}
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}
	p, _ := strconv.Atoi(port)
	// NAT may translate the port; a nonzero mapped port is sufficient for a remote probe.
	if p == 0 || addr.Port() == 0 {
		return errors.New("STUN returned a zero mapped port")
	}
	return nil
}

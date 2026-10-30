package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/gatework/derper-go/internal/config"
	"tailscale.com/client/local"
	"tailscale.com/net/stun"
)

type CheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Doctor only queries services. TLS/STUN reachability is not a claim of authorized DERP forwarding.
func Doctor(ctx context.Context, c config.Config) []CheckResult {
	var out []CheckResult
	add := func(name, detail string, err error) {
		if err != nil {
			detail = err.Error()
		}
		out = append(out, CheckResult{name, err == nil, detail})
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, c.Hostname)
	add("dns", fmt.Sprint(ips), err)
	_, port, _ := net.SplitHostPort(c.Listen)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: c.Hostname, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(c.Hostname, port))
	detail := ""
	if err == nil {
		tlsConn := conn.(*tls.Conn)
		detail = tlsConn.ConnectionState().PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
		conn.Close()
	}
	add("tls", detail, err)
	if c.STUN.Enabled {
		_, p, _ := net.SplitHostPort(c.STUN.Listen)
		err = checkSTUN(ctx, net.JoinHostPort(c.Hostname, p))
		add("stun", "valid binding response", err)
	}
	if c.Verification.Mode == "tailscaled" {
		lc := &local.Client{Socket: c.Verification.Socket, UseSocketOnly: true}
		status, err := lc.StatusWithoutPeers(ctx)
		if err == nil && status.BackendState != "Running" {
			err = fmt.Errorf("tailscaled state: %s", status.BackendState)
		}
		add("tailscaled", "running; verify actual forwarding from two authorized tailnet devices", err)
	}
	return out
}

func checkSTUN(ctx context.Context, address string) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
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

package daemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/relay"
	"github.com/gatework/derper-go/internal/testutil"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func TestReloadKeepsLiveRelayAndRejectsPartialConfiguration(t *testing.T) {
	// Unix socket paths must stay below the platform's sockaddr limit.
	dir, err := os.MkdirTemp("", "dgr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Mkdir(filepath.Join(dir, "run"), 0700); err != nil {
		t.Fatal(err)
	}
	first, second := testutil.Cert(t, "relay.example.com", 1), testutil.Cert(t, "relay.example.com", 2)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePair := func(cert testutil.Certificate) {
		t.Helper()
		if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePair(first)
	live := &liveCertificate{}
	live.set(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &first.Pair, nil })
	get := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return live.current.Load().get(hello) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := relay.Bind(ctx, relay.Options{Domain: "relay.example.com", Listen: "127.0.0.1:0", HTTPPort: -1, MaxConnections: 4}, key.NewNode(), get, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		server.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	no := false
	c := config.Config{Domain: "relay.example.com", Certificate: config.Certificate{File: certPath, Key: keyPath}, DNS: config.DNS{Publish: &no}, STUN: config.STUN{Enabled: &no}, Admission: config.Admission{Mode: config.Public}, Relay: config.Relay{Listen: server.Addr().String(), MaxConnections: 4}}
	path := filepath.Join(dir, "config.json")
	save := func() {
		t.Helper()
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	current, err := c.Resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := startReloadControl(dir, path, func(ctx context.Context, preview bool) (ReloadPlan, error) {
		return reloadConfiguration(ctx, path, &current, server, nil, live, preview)
	}, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	info, err := os.Stat(controlPath(dir))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("control permissions", err)
	}
	monitor := netmon.NewStatic()
	defer monitor.Close()
	newClient := func(private key.NodePrivate) *derphttp.Client {
		t.Helper()
		client, err := derphttp.NewClient(private, "https://relay.example.com/derp", func(string, ...any) {}, monitor)
		if err != nil {
			t.Fatal(err)
		}
		client.TLSConfig = &tls.Config{RootCAs: first.Roots, ServerName: "relay.example.com"}
		client.SetURLDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Addr().String())
		})
		t.Cleanup(func() { client.Close() })
		return client
	}
	receive := func(client *derphttp.Client) derp.ReceivedMessage {
		t.Helper()
		type result struct {
			message derp.ReceivedMessage
			err     error
		}
		ch := make(chan result, 1)
		go func() { m, e := client.Recv(); ch <- result{m, e} }()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatal(r.err)
			}
			return r.message
		case <-time.After(3 * time.Second):
			client.Close()
			t.Fatal("relay receive timed out")
			return nil
		}
	}
	aKey, bKey := key.NewNode(), key.NewNode()
	a, b := newClient(aKey), newClient(bKey)
	_ = receive(a)
	_ = receive(b)
	writePair(second)
	c.Relay.MaxConnections = 1
	c.Relay.Homepage = "https://example.com"
	save()
	plan, err := PreviewReload(ctx, dir, path)
	if err != nil || len(plan.Changes) == 0 || plan.RequiresRestart || current.MaxConnections != 4 || server.Connections().Limit != 4 {
		t.Fatal("preview applied configuration", plan, err)
	}
	if pair, err := get(nil); err != nil || pair.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("preview replaced live certificate", err)
	}
	if err = Reload(ctx, dir, path); err != nil {
		t.Fatal(err)
	}
	if server.Connections().Active != 2 || server.Connections().Limit != 1 {
		t.Fatal("reload closed established clients", server.Connections())
	}
	payload := []byte("preserved-connection-after-reload")
	if err = a.Send(bKey.Public(), payload); err != nil {
		t.Fatal(err)
	}
	packet, ok := receive(b).(derp.ReceivedPacket)
	if !ok || string(packet.Data) != string(payload) || packet.Source != aKey.Public() {
		t.Fatal("relay interrupted", packet)
	}
	c.Relay.MaxConnections = 4
	save()
	if err = Reload(ctx, dir, path); err != nil {
		t.Fatal(err)
	}
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Addr().String(), &tls.Config{RootCAs: second.Roots, ServerName: "relay.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if serial := connection.ConnectionState().PeerCertificates[0].SerialNumber.Int64(); serial != 2 {
		t.Fatal("manual certificate not reloaded", serial)
	}
	connection.Close()
	c.Relay.Listen = "127.0.0.1:1"
	c.Relay.MaxConnections = 9
	save()
	if plan, err := PreviewReload(ctx, dir, path); err == nil || !plan.RequiresRestart || server.Connections().Limit != 4 {
		t.Fatal("restart requirement lost", plan, err)
	}
	if err = Reload(ctx, dir, path); err == nil || server.Connections().Limit != 4 {
		t.Fatal("structural reload partially applied", err)
	}
	c.Relay.Listen = server.Addr().String()
	save()
	if err = os.WriteFile(keyPath, []byte("incomplete-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Reload(ctx, dir, path); err == nil || server.Connections().Limit != 4 {
		t.Fatal("invalid certificate partially applied", err)
	}
	if pair, err := get(nil); err != nil || pair.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("valid certificate was discarded", err)
	}
}

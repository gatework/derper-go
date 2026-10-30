package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gatework/derper-go/internal/tailnet"
	"github.com/gatework/derper-go/internal/testutil"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/net/wsconn"
	"tailscale.com/types/key"
)

func start(t *testing.T, c Options, get CertificateSource) (*Server, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Bind(ctx, c, key.NewNode(), get, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() { cancel(); s.Close() })
	return s, cancel, done
}
func relayConfig() Options {
	return Options{Domain: "relay.example.com", Listen: "127.0.0.1:0", STUNListen: "127.0.0.1:0", STUNEnabled: true, HTTPPort: -1}

}
func client(t *testing.T, s *Server, k key.NodePrivate, cert testutil.Certificate) *derphttp.Client {
	t.Helper()
	mon := netmon.NewStatic()
	t.Cleanup(func() { mon.Close() })
	c, err := derphttp.NewClient(k, "https://relay.example.com/derp", t.Logf, mon)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSConfig = &tls.Config{RootCAs: cert.Roots, ServerName: "relay.example.com"}
	c.SetURLDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", s.Addr().String())
	})
	t.Cleanup(func() { c.Close() })
	return c
}

type receiver interface {
	Recv() (derp.ReceivedMessage, error)
}

func receive(t *testing.T, c receiver) (derp.ReceivedMessage, error) {
	t.Helper()
	type result struct {
		m derp.ReceivedMessage
		e error
	}
	done := make(chan result, 1)
	go func() { m, e := c.Recv(); done <- result{m, e} }()
	select {
	case r := <-done:
		return r.m, r.e
	case <-time.After(4 * time.Second):
		t.Fatal("DERP receive timed out")
		return nil, context.DeadlineExceeded
	}
}
func exchange(t *testing.T, sender *derphttp.Client, receiver receiver, target, source key.NodePublic) {
	t.Helper()
	payload := []byte("opaque-wireguard-payload")
	if err := sender.Send(target, payload); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		m, err := receive(t, receiver)
		if err != nil {
			t.Fatal(err)
		}
		if p, ok := m.(derp.ReceivedPacket); ok {
			if p.Source != source || string(p.Data) != string(payload) {
				t.Fatal("forwarded packet mismatch")
			}
			return
		}
	}
	t.Fatal("no forwarded packet")
}

func TestRelayForwardingHotCertificateAndShutdown(t *testing.T) {
	first := testutil.Cert(t, "relay.example.com", 11)
	second := testutil.Cert(t, "relay.example.com", 12)
	var current atomic.Pointer[tls.Certificate]
	current.Store(&first.Pair)
	s, cancel, done := start(t, relayConfig(), func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil })
	a, b := key.NewNode(), key.NewNode()
	ca, cb := client(t, s, a, first), client(t, s, b, first)
	for _, c := range []*derphttp.Client{ca, cb} {
		m, err := receive(t, c)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := m.(derp.ServerInfoMessage); !ok {
			t.Fatalf("unexpected %T", m)
		}
	}
	exchange(t, ca, cb, b.Public(), a.Public())
	current.Store(&second.Pair)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addr().String(), &tls.Config{RootCAs: second.Roots, ServerName: "relay.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	peers := conn.ConnectionState().PeerCertificates
	conn.Close()
	if peers[0].SerialNumber.Int64() != 12 || len(peers) != 3 {
		t.Fatal("new certificate or DERP metadata missing")
	}
	if len(first.Pair.Certificate) != 2 || len(second.Pair.Certificate) != 2 {
		t.Fatal("shared certificate mutated")
	}
	exchange(t, cb, ca, a.Public(), b.Public())
	address := s.Addr().String()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown retained connections")
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("listener leaked:", err)
	}
	ln.Close()
}

func TestPrivateRelayRejectsUnknownAndUnavailableTailscaled(t *testing.T) {
	good := key.NewNode()
	dir, err := os.MkdirTemp("", "dg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "tailscaled.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var hang atomic.Bool
	api := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hang.Load() {
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/localapi/v0/whois" && r.URL.Query().Get("addr") == good.Public().String() {
			fmt.Fprint(w, `{"Node":{}}`)
			return
		}
		http.NotFound(w, r)
	})}
	go api.Serve(ln)
	t.Cleanup(func() { api.Close() })
	c := relayConfig()
	c.Verifier = tailnet.New(tailnet.Options{Socket: socket})
	t.Cleanup(c.Verifier.(*tailnet.Verifier).Close)
	cert := testutil.Cert(t, c.Domain, 1)
	s, _, _ := start(t, c, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil })
	if _, err := receive(t, client(t, s, good, cert)); err != nil {
		t.Fatal("authorized client rejected:", err)
	}
	if _, err := receive(t, client(t, s, key.NewNode(), cert)); err == nil {
		t.Fatal("unknown client admitted")
	}
	hang.Store(true)
	if _, err := receive(t, client(t, s, good, cert)); err == nil {
		t.Fatal("unresponsive tailscaled failed open")
	}
	api.Close()
	if _, err := receive(t, client(t, s, good, cert)); err == nil {
		t.Fatal("unavailable tailscaled failed open")
	}
}

func TestSTUNTransactionAndAddress(t *testing.T) {
	c := relayConfig()
	cert := testutil.Cert(t, c.Domain, 1)
	s, _, _ := start(t, c, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil })
	conn, err := net.Dial("udp", s.STUNAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	tx := stun.NewTxID()
	if _, err = conn.Write(stun.Request(tx)); err != nil {
		t.Fatal(err)
	}
	var b [1024]byte
	n, err := conn.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	got, addr, err := stun.ParseResponse(b[:n])
	if err != nil || got != tx || addr.String() != conn.LocalAddr().String() {
		t.Fatalf("transaction/address mismatch: %v %v", addr, err)
	}
}

func TestShutdownCancelsPendingClientVerification(t *testing.T) {
	dir, err := os.MkdirTemp("", "dg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "tailscaled.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	started, canceled := make(chan struct{}, 1), make(chan struct{}, 1)
	api := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
	})}
	go api.Serve(ln)
	t.Cleanup(func() { api.Close() })
	c := relayConfig()
	c.Verifier = tailnet.New(tailnet.Options{Socket: socket})
	t.Cleanup(c.Verifier.(*tailnet.Verifier).Close)
	cert := testutil.Cert(t, c.Domain, 1)
	s, cancel, done := start(t, c, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil })
	cc := client(t, s, key.NewNode(), cert)
	clientDone := make(chan error, 1)
	go func() { _, err := cc.Recv(); clientDone <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("verification did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for admission timeout")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("local API query survived shutdown")
	}
	select {
	case err := <-clientDone:
		if err == nil {
			t.Fatal("client admitted during shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("pending DERP connection survived shutdown")
	}
}

func TestWebSocketDERP(t *testing.T) {
	c := relayConfig()
	cert := testutil.Cert(t, c.Domain, 1)
	s, _, _ := start(t, c, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cert.Roots, ServerName: c.Domain}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", s.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	ws, _, err := websocket.Dial(ctx, "wss://relay.example.com/derp", &websocket.DialOptions{Subprotocols: []string{"derp"}, HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	conn := wsconn.NetConn(ctx, ws, websocket.MessageBinary, "")
	k := key.NewNode()
	dc, err := derp.NewClient(k, conn, bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = receive(t, dc); err != nil {
		t.Fatal(err)
	}
	sender := key.NewNode()
	cc := client(t, s, sender, cert)
	if _, err = receive(t, cc); err != nil {
		t.Fatal(err)
	}
	exchange(t, cc, dc, k.Public(), sender.Public())
}

func TestBindConflictReturnsError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c := relayConfig()
	c.Listen = ln.Addr().String()
	cert := testutil.Cert(t, c.Domain, 1)
	if _, err = Bind(context.Background(), c, key.NewNode(), func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil }, slog.Default()); err == nil {
		t.Fatal("occupied listener accepted")
	}
}

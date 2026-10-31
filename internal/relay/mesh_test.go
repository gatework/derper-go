package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/derper-go/internal/testutil"
	"tailscale.com/derp"
	"tailscale.com/types/key"
)

func TestMeshForwardsAcrossTwoRelaysAndJoinsOnClose(t *testing.T) {
	cert := testutil.Cert(t, "relay.example.com", 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := relayConfig()
	options.Mesh = &MeshOptions{Key: strings.Repeat("ab", 32)}
	first, err := Bind(ctx, options, key.NewNode(), func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil }, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, firstPort, _ := net.SplitHostPort(first.Addr().String())
	options.Mesh = &MeshOptions{Key: options.Mesh.Key, Peers: []MeshPeer{{Host: net.JoinHostPort("relay.example.com", firstPort), Dial: first.Addr().String()}}}
	second, err := Bind(ctx, options, key.NewNode(), func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil }, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_, secondPort, _ := net.SplitHostPort(second.Addr().String())
	if err = first.prepareMesh(&MeshOptions{Key: options.Mesh.Key, Peers: []MeshPeer{{Host: net.JoinHostPort("relay.example.com", secondPort), Dial: second.Addr().String()}}}, logger, ctx); err != nil {
		t.Fatal(err)
	}
	for _, server := range []*Server{first, second} {
		for _, client := range server.mesh.clients {
			client.TLSConfig = &tls.Config{RootCAs: cert.Roots, ServerName: "relay.example.com"}
		}
	}
	done := make(chan error, 2)
	go func() { done <- first.Serve(ctx) }()
	go func() { done <- second.Serve(ctx) }()
	a, b := key.NewNode(), key.NewNode()
	ca, cb := client(t, first, a, cert), client(t, second, b, cert)
	for _, c := range []receiver{ca, cb} {
		if m, err := receive(t, c); err != nil {
			t.Fatal(err)
		} else if _, ok := m.(derp.ServerInfoMessage); !ok {
			t.Fatal(m)
		}
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := true
		for _, server := range []*Server{first, second} {
			var stats map[string]any
			if err = json.Unmarshal([]byte(server.core.ExpVar(false).String()), &stats); err != nil {
				t.Fatal(err)
			}
			if stats["gauge_clients_remote"].(float64) < 1 {
				ready = false
			}
		}
		if ready {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("mesh did not register forwarding routes")
		case <-ticker.C:
		}
	}
	exchange(t, ca, cb, b.Public(), a.Public())
	exchange(t, cb, ca, a.Public(), b.Public())
	cancel()
	first.Close()
	second.Close()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("mesh shutdown blocked")
		}
	}
	if first.Connections().Active != 0 || second.Connections().Active != 0 {
		t.Fatal("mesh retained inbound connections")
	}
}

func TestMeshSecretUsesSystemdSnapshotAndNeverEchoesValue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	value := strings.Repeat("AB", 32)
	path := filepath.Join(dir, "mesh-key")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMeshKey("/unreadable/source"); err == nil || strings.Contains(err.Error(), value) {
		t.Fatal("invalid key accepted or exposed", err)
	}
	value = strings.ToLower(value)
	if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadMeshKey("/unreadable/source"); err != nil || got != value {
		t.Fatal("snapshot not used", err)
	}
}

func TestMeshSelfEntryDoesNotConsumeConnectionQuota(t *testing.T) {
	cert := testutil.Cert(t, "relay.example.com", 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := relayConfig()
	options.MaxConnections = 1
	options.Mesh = &MeshOptions{Key: strings.Repeat("ab", 32)}
	server, err := Bind(ctx, options, key.NewNode(), func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil }, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Addr().String())
	if err = server.prepareMesh(&MeshOptions{Key: options.Mesh.Key, Peers: []MeshPeer{{Host: net.JoinHostPort("relay.example.com", port), Dial: server.Addr().String()}}}, logger, ctx); err != nil {
		t.Fatal(err)
	}
	server.mesh.clients[0].TLSConfig = &tls.Config{RootCAs: cert.Roots, ServerName: "relay.example.com"}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for server.Mesh().Ignored != 1 || server.Connections().Active != 0 {
		select {
		case <-deadline.C:
			t.Fatal("self mesh retained quota", server.Mesh(), server.Connections())
		case <-ticker.C:
		}
	}
	native := client(t, server, key.NewNode(), cert)
	if _, err := receive(t, native); err != nil {
		t.Fatal("self entry starved real clients", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

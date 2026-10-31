package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/gatework/derper-go/internal/fileio"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
)

type MeshPeer struct{ Host, Dial string }
type MeshOptions struct {
	Key   string
	Peers []MeshPeer
}
type MeshStats struct{ Peers, Connected int }
type meshState struct {
	mu              sync.Mutex
	started, closed bool
	ctx             context.Context
	clients         []*derphttp.Client
	monitor         *netmon.Monitor
	wg              sync.WaitGroup
	logf            func(string, ...any)
}

func (s *Server) prepareMesh(options *MeshOptions, logger *slog.Logger, ctx context.Context) error {
	if options == nil {
		return nil
	}
	if err := s.core.SetMeshKey(options.Key); err != nil {
		return errors.New("节点互联密钥必须是 64 个小写十六进制字符（32 字节）")
	}
	if !s.core.HasMeshKey() {
		return errors.New("节点互联密钥不能为全零")
	}
	s.mesh.ctx = ctx
	s.mesh.logf = func(format string, args ...any) {
		if logger.Enabled(ctx, slog.LevelDebug) {
			logger.DebugContext(ctx, "节点互联", "detail", format, "args", args)
		}
	}
	if len(options.Peers) == 0 {
		return nil
	}
	s.mesh.monitor = netmon.NewStatic()
	for _, peer := range options.Peers {
		client, err := derphttp.NewClient(s.core.PrivateKey(), "https://"+peer.Host+"/derp", s.mesh.logf, s.mesh.monitor)
		if err != nil {
			return errors.New("节点互联地址无效")
		}
		client.MeshKey = s.core.MeshKey()
		client.WatchConnectionChanges = true
		if peer.Dial != "" {
			client.SetURLDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
				target := peer.Dial
				if _, _, err := net.SplitHostPort(target); err != nil {
					_, port, err := net.SplitHostPort(address)
					if err != nil {
						return nil, err
					}
					target = net.JoinHostPort(strings.Trim(target, "[]"), port)
				}
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target)
			})
		}
		s.mesh.clients = append(s.mesh.clients, client)
	}
	return nil
}
func (s *Server) startMesh() {
	s.mesh.mu.Lock()
	defer s.mesh.mu.Unlock()
	if s.mesh.closed || s.mesh.started {
		return
	}
	s.mesh.started = true
	for _, client := range s.mesh.clients {
		s.mesh.wg.Go(func() {
			client.RunWatchConnectionLoop(s.mesh.ctx, s.core.PublicKey(), s.mesh.logf,
				func(peer derp.PeerPresentMessage) { s.core.AddPacketForwarder(peer.Key, client) },
				func(peer derp.PeerGoneMessage) { s.core.RemovePacketForwarder(peer.Peer, client) }, nil)
		})
	}
}
func (s *Server) closeMesh() {
	s.mesh.mu.Lock()
	s.mesh.closed = true
	s.mesh.mu.Unlock()
	for _, client := range s.mesh.clients {
		client.Close()
	}
	s.mesh.wg.Wait()
	if s.mesh.monitor != nil {
		s.mesh.monitor.Close()
	}
}
func (s *Server) Mesh() MeshStats {
	result := MeshStats{Peers: len(s.mesh.clients)}
	for _, client := range s.mesh.clients {
		if _, connected := client.TLSConnectionState(); connected {
			result.Connected++
		}
	}
	return result
}

// LoadMeshKey validates the shared secret without echoing it in diagnostics.
func LoadMeshKey(path string) (string, error) {
	data, err := fileio.ReadRegularFile(fileio.CredentialPath("mesh-key", path), 128)
	if err != nil {
		return "", errors.New("无法读取节点互联密钥文件，请检查路径和权限")
	}
	value := strings.TrimSpace(string(data))
	if len(value) != 64 || strings.ToLower(value) != value {
		return "", errors.New("节点互联密钥必须是 64 个小写十六进制字符（32 字节）")
	}
	if _, err = hex.DecodeString(value); err != nil || value == strings.Repeat("0", 64) {
		return "", errors.New("节点互联密钥必须是 64 个小写十六进制字符（32 字节）")
	}
	return value, nil
}

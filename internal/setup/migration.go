package setup

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/tailnet"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func inspectMigrationRegion(ctx context.Context, s config.Settings) error {
	v := tailnet.New(tailnet.Options{Socket: s.Socket})
	defer v.Close()
	if err := v.Check(ctx); err != nil {
		return err
	}
	return v.ReuseRegion(ctx, s.Region, s.Domain, s.Port)
}

// A busy HTTPS listener is acceptable only when its authenticated server key is
// exactly the imported identity. No remote service is stopped by initialization.
func inspectRelayIdentity(ctx context.Context, s config.Settings, identity []byte) error {
	private, err := state.DecodeIdentity(identity)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	monitor := netmon.NewStatic()
	defer monitor.Close()
	client, err := derphttp.NewClient(key.NewNode(), "https://"+s.Domain+":"+strconv.Itoa(s.Port)+"/derp", func(string, ...any) {}, monitor)
	if err != nil {
		return errors.New("无法检查原中继身份")
	}
	defer client.Close()
	host := s.ListenHost
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	client.SetURLDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(s.Port)))
	})
	if client.Connect(ctx) != nil || client.ServerPublicKey() != private.Public() {
		return errors.New("占用 HTTPS 端口的服务身份与导入身份不匹配")
	}
	return nil
}

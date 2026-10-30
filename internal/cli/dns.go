package cli

import (
	"context"
	"fmt"
	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/dns"
	"io"
)

func describeDNS(out io.Writer, changes []dns.Change) {
	for _, ch := range changes {
		action := map[string]string{"create": "创建", "update": "更新", "noop": "保留", "recover": "恢复记录", "adopt": "接管"}[ch.Action]
		fmt.Fprintf(out, "DNS：%s %s %s → %s（仅 DNS，不启用代理）\n", action, ch.After.Type, ch.After.Name, ch.After.Content)
		if ch.Before != nil && ch.Action == "adopt" {
			fmt.Fprintf(out, "  当前地址 %s，TTL %d，代理 %t\n", ch.Before.Content, ch.Before.TTL, ch.Before.Proxied)
		}
	}
}
func applyDNS(ctx context.Context, p *dns.Publisher, changes []dns.Change) error {
	var approved []cloudflare.Record
	for _, ch := range changes {
		if ch.Action == "adopt" && ch.Before != nil {
			approved = append(approved, *ch.Before)
		}
	}
	_, err := p.Apply(ctx, approved...)
	return err
}

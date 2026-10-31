package daemon

import (
	"encoding/json"
	"testing"

	"github.com/gatework/derper-go/internal/config"
	"tailscale.com/tailcfg"
)

func TestRawMapRoundTripAndDisabledSTUN(t *testing.T) {
	c := config.Settings{RelayEnabled: true, Domain: "relay.example.com", Region: 900, Port: 443, STUNEnabled: false}

	b, err := ExportTailnetConfig(c, "derpmap")
	if err != nil {
		t.Fatal(err)
	}
	var m tailcfg.DERPMap
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	node := m.Regions[900].Nodes[0]
	if node.STUNPort != -1 || node.DERPPort != 443 || node.IPv6 != "none" || node.IPv4 != "" {
		t.Fatalf("unexpected node %+v", node)
	}
}

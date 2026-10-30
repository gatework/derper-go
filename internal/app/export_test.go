package app

import (
	"encoding/json"
	"testing"

	"github.com/gatework/derper-go/internal/config"
	"tailscale.com/tailcfg"
)

func TestRawMapRoundTripAndDisabledSTUN(t *testing.T) {
	c := config.Default()
	c.Hostname = "relay.example.com"
	c.Region = config.Region{ID: 900, Code: "test", Name: "Test", Node: "test"}
	c.STUN.Enabled = false
	c.DNS.IPv4URL = "https://ip.example.com"
	b, err := Export(c, "derpmap")
	if err != nil {
		t.Fatal(err)
	}
	var m tailcfg.DERPMap
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	node := m.Regions[900].Nodes[0]
	if node.STUNPort != -1 || node.DERPPort != 8443 || node.IPv6 != "none" || node.IPv4 != "" {
		t.Fatalf("unexpected node %+v", node)
	}
}

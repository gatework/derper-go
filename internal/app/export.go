package app

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/gatework/derper-go/internal/config"
	"tailscale.com/tailcfg"
)

func DERPMap(c config.Config) *tailcfg.DERPMap {
	_, port, _ := net.SplitHostPort(c.Listen)
	derpPort, _ := strconv.Atoi(port)
	stunPort := -1
	if c.STUN.Enabled {
		_, p, _ := net.SplitHostPort(c.STUN.Listen)
		stunPort, _ = strconv.Atoi(p)
	}
	ipv6 := c.DNS.IPv6
	if ipv6 == "" {
		ipv6 = "none"
	}
	id := tailcfg.DERPRegionID(c.Region.ID)
	node := &tailcfg.DERPNode{Name: c.Region.Node, RegionID: id, HostName: c.Hostname, IPv4: c.DNS.IPv4, IPv6: ipv6, DERPPort: derpPort, STUNPort: stunPort}
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{id: {RegionID: id, RegionCode: c.Region.Code, RegionName: c.Region.Name, Nodes: []*tailcfg.DERPNode{node}}}}
}

func Export(c config.Config, format string) ([]byte, error) {
	m := DERPMap(c)
	var value any = m
	switch format {
	case "derpmap":
	case "policy":
		value = map[string]any{"derpMap": map[string]any{"omitDefaultRegions": false, "regions": m.Regions}}
	default:
		return nil, fmt.Errorf("format must be policy or derpmap")
	}
	b, err := json.MarshalIndent(value, "", "  ")
	return append(b, '\n'), err
}

package daemon

import (
	"encoding/json"
	"fmt"

	"github.com/gatework/derper-go/internal/config"
	"tailscale.com/tailcfg"
)

func DERPMap(c config.Settings) *tailcfg.DERPMap {
	stunPort := -1
	if c.STUNEnabled {
		stunPort = c.STUNPort
	}
	ipv4, ipv6 := "", "none"
	if c.IPv4.IsValid() {
		ipv4 = c.IPv4.String()
	}
	if c.IPv6.IsValid() {
		ipv6 = c.IPv6.String()
	}
	id := tailcfg.DERPRegionID(c.Region)
	node := &tailcfg.DERPNode{Name: fmt.Sprintf("relay-%d", id), RegionID: id, HostName: c.Domain, IPv4: ipv4, IPv6: ipv6, DERPPort: c.Port, STUNPort: stunPort}
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{id: {RegionID: id, RegionCode: fmt.Sprintf("relay-%d", id), RegionName: c.Domain, Nodes: []*tailcfg.DERPNode{node}}}}
}

type regionPolicy struct {
	OmitDefaultRegions bool                                         `json:"omitDefaultRegions"`
	Regions            map[tailcfg.DERPRegionID]*tailcfg.DERPRegion `json:"regions"`
}
type policyFragment struct {
	DERPMap regionPolicy `json:"derpMap"`
}

func ExportTailnetConfig(c config.Settings, format string) ([]byte, error) {
	m := DERPMap(c)
	var value any = m
	switch format {
	case "derpmap":
	case "policy":
		value = policyFragment{DERPMap: regionPolicy{Regions: m.Regions}}
	default:
		return nil, fmt.Errorf("输出格式应为 policy 或 derpmap")
	}
	b, err := json.MarshalIndent(value, "", "  ")
	return append(b, '\n'), err
}

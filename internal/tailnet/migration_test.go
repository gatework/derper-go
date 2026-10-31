package tailnet

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"tailscale.com/tailcfg"
	"testing"
)

func TestMigrationRegionMustIdentifyExactlyOneMatchingEndpoint(t *testing.T) {
	dir, err := os.MkdirTemp("", "dgm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "tailscaled.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var regions atomic.Pointer[tailcfg.DERPMap]
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(regions.Load()) })}
	go server.Serve(listener)
	defer server.Close()
	v := New(Options{Socket: socket})
	defer v.Close()
	for _, tt := range []struct {
		name  string
		nodes []*tailcfg.DERPNode
		ok    bool
	}{
		{"matching", []*tailcfg.DERPNode{{HostName: "Relay.Example.com.", DERPPort: 8443}}, true},
		{"different domain", []*tailcfg.DERPNode{{HostName: "other.example.com", DERPPort: 8443}}, false},
		{"different port", []*tailcfg.DERPNode{{HostName: "relay.example.com"}}, false},
		{"multiple nodes", []*tailcfg.DERPNode{{HostName: "relay.example.com", DERPPort: 8443}, {HostName: "peer.example.com"}}, false},
		{"missing node", []*tailcfg.DERPNode{nil}, false},
		{"STUN only", []*tailcfg.DERPNode{{HostName: "relay.example.com", DERPPort: 8443, STUNOnly: true}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			regions.Store(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{902: {RegionID: 902, Nodes: tt.nodes}}})
			err := v.ReuseRegion(context.Background(), 902, "relay.example.com", 8443)
			if (err == nil) != tt.ok {
				t.Fatal(err)
			}
		})
	}
}

package tailnet

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"tailscale.com/tailcfg"
	"testing"
)

func TestRegionDiscoveryAndLoginCheck(t *testing.T) {
	dir, err := os.MkdirTemp("", "dgt-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "tailscaled.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/status":
			json.NewEncoder(w).Encode(map[string]string{"BackendState": "Running"})
		case "/localapi/v0/derpmap":
			json.NewEncoder(w).Encode(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{900: {RegionID: 900}, 902: {RegionID: 902}}})
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(ln)
	defer server.Close()
	verifier := New(socket)
	defer verifier.Close()
	if err = verifier.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	id, err := verifier.Region(context.Background(), 0)
	if err != nil || id != 901 {
		t.Fatal(id, err)
	}
	if _, err = verifier.Region(context.Background(), 900); err == nil {
		t.Fatal("region collision accepted")
	}
	server.Close()
	if err = verifier.Check(context.Background()); err == nil {
		t.Fatal("unavailable tailscaled accepted")
	}
}

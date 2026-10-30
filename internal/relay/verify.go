package relay

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
)

// bindVerifier uses the upstream admission hook so local API queries have a
// deadline and are canceled at shutdown. The upstream direct local-client path
// has neither an HTTP timeout nor a cancelable context after native HTTP hijack.
func (s *Server) bindVerifier(ctx context.Context, socket string) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.verifierListener = ln
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}, ResponseHeaderTimeout: 3 * time.Second, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: time.Minute}
	s.verifierTransport = transport
	client := &local.Client{Socket: socket, UseSocketOnly: true, Transport: transport}
	s.verifier = &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Minute, BaseContext: func(net.Listener) context.Context { return ctx }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/verify" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req tailcfg.DERPAdmitClientRequest
		d := json.NewDecoder(r.Body)
		if err := d.Decode(&req); err != nil || req.NodePublic.IsZero() {
			http.Error(w, "invalid admission request", http.StatusBadRequest)
			return
		}
		var extra any
		if err := d.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid admission request", http.StatusBadRequest)
			return
		}
		lookup, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		who, err := client.WhoIsNodeKey(lookup, req.NodePublic)
		allow := err == nil && who != nil && who.Node != nil
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: allow})
	})}
	s.core.SetVerifyClientURL("http://" + ln.Addr().String() + "/verify")
	return nil
}

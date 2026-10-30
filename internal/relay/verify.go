package relay

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"tailscale.com/tailcfg"
)

// bindVerifier uses the upstream admission hook so local API queries have a
// deadline and are canceled at shutdown. The upstream direct local-client path
// has neither an HTTP timeout nor a cancelable context after native HTTP hijack.
func (s *Server) bindVerifier(ctx context.Context, verifier NodeVerifier) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.verifierListener = ln
	s.verifier = &http.Server{MaxHeaderBytes: 4096, ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Minute, BaseContext: func(net.Listener) context.Context { return ctx }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		allow := verifier.VerifyNode(lookup, req.NodePublic) == nil
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: allow})
	})}
	s.core.SetVerifyClientURL("http://" + ln.Addr().String() + "/verify")
	return nil
}

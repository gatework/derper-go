// Package relay adapts upstream DERP/STUN primitives to an owned lifecycle.
package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/ktimeout"
	"tailscale.com/net/stunserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type CertificateSource func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// Options describes relay listeners and admission, independent of user configuration.
type TCPOptions struct{ Keepalive, UserTimeout, WriteTimeout time.Duration }
type Options struct {
	Disabled                   bool
	Homepage                   string
	TCP                        *TCPOptions
	ConnectionRate             float64
	ConnectionBurst            int
	BlockedApps                []string
	AdmissionTimeout           time.Duration
	Mesh                       *MeshOptions
	Bootstrap                  http.Handler
	Domain, Listen, STUNListen string
	STUNEnabled                bool
	MaxConnections             int
	HTTPPort                   int            // -1 disables the captive-portal probe listener.
	Verifier                   ClientVerifier // nil explicitly permits public clients.
}
type ClientVerifier interface {
	VerifyClient(context.Context, tailcfg.DERPAdmitClientRequest) error
}

type Server struct {
	mesh        meshState
	ready       chan struct{}
	connections *connectionLimit

	core             *derpserver.Server
	tlsServer        *http.Server
	httpServer       *http.Server
	tcp              net.Listener
	httpListener     net.Listener
	verifier         *http.Server
	verifierListener net.Listener
	stun             *stunserver.STUNServer
	cancel           context.CancelFunc
	closeOnce        sync.Once
	closed           chan struct{}
}

// Bind claims every enabled listener before certificate issuance or DNS writes.
func Bind(parent context.Context, c Options, identity key.NodePrivate, certificate CertificateSource, logger *slog.Logger) (s *Server, err error) {
	ctx, cancel := context.WithCancel(parent)
	limit := c.MaxConnections
	if limit <= 0 {
		limit = DefaultMaxConnections
	}
	s = &Server{connections: &connectionLimit{limit: int64(limit)}, cancel: cancel, closed: make(chan struct{}), ready: make(chan struct{})}
	defer func(bound *Server) {
		if err != nil {
			bound.Close()
		}
	}(s)
	logf := func(format string, args ...any) {
		if logger.Enabled(ctx, slog.LevelDebug) {
			logger.DebugContext(ctx, fmt.Sprintf(format, args...))
		}
	}
	s.core = derpserver.New(identity, logf)
	s.core.SetVerifyClientURLFailOpen(false)
	tcp := TCPOptions{Keepalive: 10 * time.Minute, UserTimeout: 15 * time.Second, WriteTimeout: derpserver.DefaultTCPWiteTimeout}
	if c.TCP != nil {
		tcp = *c.TCP
	}
	s.core.SetTCPWriteTimeout(tcp.WriteTimeout)
	s.core.SetDisallowedAppNames(c.BlockedApps)
	if c.ConnectionRate > 0 {
		s.connections.setRate(c.ConnectionRate, c.ConnectionBurst)
	}
	if err = s.prepareMesh(c.Mesh, logger, ctx); err != nil {
		return nil, err
	}
	if c.Verifier != nil {
		if err = s.bindVerifier(ctx, c.Verifier, c.AdmissionTimeout); err != nil {
			return nil, err
		}
	}
	mux := http.NewServeMux()
	if !c.Disabled {
		mux.Handle("/derp", derpserver.AddWebSocketSupport(s.core, derpserver.Handler(s.core)))
	}
	if c.Bootstrap != nil {
		mux.Handle("/bootstrap-dns", c.Bootstrap)
	}
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	mux.HandleFunc("/derp/latency-check", derpserver.ProbeHandler)
	mux.HandleFunc("/generate_204", derpserver.ServeNoContent)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if c.Homepage != "" && c.Homepage != "blank" {
			http.Redirect(w, r, c.Homepage, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	})
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certificate, NextProtos: []string{"http/1.1"}}
	if !c.Disabled {
		s.core.ModifyTLSConfigToAddMetaCert(tlsConfig)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	s.tlsServer = &http.Server{Handler: mux, TLSConfig: tlsConfig, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelDebug)}
	keepalive := tcp.Keepalive
	if keepalive == 0 {
		keepalive = -1
	}
	lc := net.ListenConfig{KeepAlive: keepalive, Control: ktimeout.UserTimeout(tcp.UserTimeout)}
	lc.SetMultipathTCP(false)
	s.tcp, err = lc.Listen(ctx, "tcp", c.Listen)
	if err != nil {
		return nil, err
	}
	s.tcp = &limitedListener{Listener: s.tcp, limit: s.connections}
	if c.STUNEnabled {
		s.stun = stunserver.New(ctx)
		if err = s.stun.Listen(c.STUNListen); err != nil {
			return nil, err
		}
	}
	if c.HTTPPort != -1 {
		host, _, _ := net.SplitHostPort(c.Listen)
		s.httpListener, err = lc.Listen(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(c.HTTPPort)))
		if err != nil {
			return nil, err
		}
		s.httpListener = &limitedListener{Listener: s.httpListener, limit: s.connections}
		httpMux := http.NewServeMux()
		httpMux.HandleFunc("/generate_204", derpserver.ServeNoContent)
		s.httpServer = &http.Server{Handler: httpMux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	}
	return s, nil
}

func (s *Server) Connections() ConnectionStats { return s.connections.stats() }

func (s *Server) Addr() net.Addr { return s.tcp.Addr() }
func (s *Server) STUNAddr() net.Addr {
	if s.stun == nil {
		return nil
	}
	return s.stun.LocalAddr()
}
func (s *Server) PublicKey() key.NodePublic { return s.core.PublicKey() }

// Serve blocks until cancellation or a fatal listener error; every worker is joined.
func (s *Server) Serve(ctx context.Context) error {
	s.startMesh()
	results := make(chan error, 4)
	count := 1
	if s.verifier != nil {
		count++
		go func() { results <- s.verifier.Serve(s.verifierListener) }()
	}
	go func() { results <- s.tlsServer.ServeTLS(&readyListener{Listener: s.tcp, ready: s.ready}, "", "") }()
	if s.stun != nil {
		count++
		go func() { results <- s.stun.Serve() }()
	}
	if s.httpServer != nil {
		count++
		go func() { results <- s.httpServer.Serve(s.httpListener) }()
	}
	var first error
	select {
	case first = <-results:
		count--
	case <-ctx.Done():
	case <-s.closed:
	}
	s.Close()
	for range count {
		first = errors.Join(first, <-results)
	}
	return ignoreClosed(first)
}

func ignoreClosed(err error) error {
	if err == nil {
		return nil
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		var result error
		for _, e := range many.Unwrap() {
			result = errors.Join(result, ignoreClosed(e))
		}
		return result
	}
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.closeMesh()
		if s.tcp != nil {
			_ = s.tcp.Close()
		}
		if s.httpListener != nil {
			_ = s.httpListener.Close()
		}
		if s.verifierListener != nil {
			_ = s.verifierListener.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if s.verifier != nil {
			if err := s.verifier.Shutdown(ctx); err != nil {
				_ = s.verifier.Close()
			}
		}
		// net/http does not own hijacked DERP connections.
		if s.core != nil {
			_ = s.core.Close()
		}
		if s.tlsServer != nil {
			if err := s.tlsServer.Shutdown(ctx); err != nil {
				_ = s.tlsServer.Close()
			}
		}
		if s.httpServer != nil {
			if err := s.httpServer.Shutdown(ctx); err != nil {
				_ = s.httpServer.Close()
			}
		}
		close(s.closed)
	})
}

// Ready closes only after ServeTLS has entered its accept loop.
func (s *Server) Ready() <-chan struct{} { return s.ready }

type readyListener struct {
	net.Listener
	ready chan struct{}
	once  sync.Once
}

func (l *readyListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.ready) })
	return l.Listener.Accept()
}

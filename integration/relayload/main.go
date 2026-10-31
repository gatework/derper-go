// relayload is an isolated benchmark fixture, never a production entry point.
// It drives the real daemon in one process and DERP clients in another.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	_ "net/http/pprof" // reachable only on the fixture's loopback control listener
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/daemon"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

const control = "http://127.0.0.1:19090"
const address = "127.0.0.1:19443"
const payloadSize = 1200

func main() {
	mode := flag.String("mode", "client", "server or client")
	scenario := flag.String("scenario", "forward", "forward, idle, slow, reconnect, or admission")
	connections := flag.Int("connections", 1000, "even number of connected nodes")
	profiles := flag.Bool("profiles", false, "enable mutex and block profiling in fixture")
	duration := flag.Duration("duration", 10*time.Minute, "measured duration")
	flag.Parse()
	if os.Getenv("DERPER_GO_LOAD_TEST") != "1" {
		fmt.Fprintln(os.Stderr, "requires DERPER_GO_LOAD_TEST=1 in an isolated test environment")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	if *mode == "server" {
		if *profiles {
			runtime.SetMutexProfileFraction(1)
			runtime.SetBlockProfileRate(10000)
		}
		err = serve(ctx)
	} else if *mode == "client" && *connections >= 2 && *connections <= 10000 && *connections%2 == 0 && *duration > 0 {
		err = runClient(ctx, *scenario, *connections, *duration)
	} else {
		err = errors.New("invalid benchmark arguments")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type resources struct {
	MaxRSS         uint64        `json:"max_rss_bytes"`
	CPUSeconds     float64       `json:"cpu_seconds"`
	RSS            uint64        `json:"rss_bytes"`
	Heap           uint64        `json:"heap_bytes"`
	Allocated      uint64        `json:"allocated_bytes"`
	GC             uint32        `json:"gc_cycles"`
	GCPause        uint64        `json:"gc_pause_ns"`
	GCCPUFraction  float64       `json:"gc_cpu_fraction"`
	Goroutines     int           `json:"goroutines"`
	FDs            int           `json:"fds"`
	MockChecks     int64         `json:"mock_checks"`
	PeakMockChecks int64         `json:"peak_mock_checks"`
	Status         daemon.Status `json:"status"`
}

func certificate(dir string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(filepath.Join(dir, "cert.pem"), public, 0600); err != nil {
		return nil, err
	}
	err = os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600)
	return public, err
}

func serve(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "relayload-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	public, err := certificate(dir)
	if err != nil {
		return err
	}
	socket := filepath.Join(dir, "tailscaled.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	var delay, active, peak atomic.Int64
	localAPI := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/status":
			io.WriteString(w, `{"BackendState":"Running"}`)
		case "/localapi/v0/whois":
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			if d := time.Duration(delay.Load()); d > 0 {
				timer := time.NewTimer(d)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
					return
				}
			}
			// This fixture authorizes only its ephemeral local benchmark connections.
			io.WriteString(w, `{"Node":{}}`)
		default:
			http.NotFound(w, r)
		}
	})}
	go localAPI.Serve(listener)
	defer localAPI.Close()
	// Build the same workload against both configuration schemas. Reflection
	// is confined to this cross-revision fixture, never the application.
	values := map[string]any{"domain": "relay.test", "certificate": map[string]string{"file": "cert.pem", "key": "key.pem"}, "dns": map[string]bool{"publish": false}, "stun": map[string]bool{"enabled": false}, "tailscale": map[string]string{"socket": socket}}
	if _, legacy := reflect.TypeOf(config.Config{}).FieldByName("Port"); legacy {
		values["port"], values["access"] = 19443, "tailnet"
	} else {
		values["relay"] = map[string]string{"listen": ":19443"}
		values["admission"] = map[string]string{"mode": "tailnet"}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	c, err := config.Decode(raw)
	if err != nil {
		return err
	}
	settings, err := c.Resolve(dir)
	if err != nil {
		return err
	}
	stateDir := filepath.Join(dir, "state")
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	mux.HandleFunc("GET /certificate", func(w http.ResponseWriter, r *http.Request) { w.Write(public) })
	mux.HandleFunc("POST /delay", func(w http.ResponseWriter, r *http.Request) {
		d, err := time.ParseDuration(r.URL.Query().Get("duration"))
		if err != nil || d < 0 || d > 10*time.Second {
			http.Error(w, "invalid delay", 400)
			return
		}
		delay.Store(int64(d))
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		var usage syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
		fds, _ := os.ReadDir("/proc/self/fd")
		var rss uint64
		if b, err := os.ReadFile("/proc/self/statm"); err == nil {
			fields := strings.Fields(string(b))
			if len(fields) > 1 {
				pages, _ := strconv.ParseUint(fields[1], 10, 64)
				rss = pages * uint64(os.Getpagesize())
			}
		}
		status, _ := daemon.ReadStatus(stateDir)
		value := resources{MaxRSS: uint64(usage.Maxrss) * 1024, CPUSeconds: float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6, RSS: rss, Heap: mem.HeapAlloc, Allocated: mem.TotalAlloc, GC: mem.NumGC, GCPause: mem.PauseTotalNs, GCCPUFraction: mem.GCCPUFraction, Goroutines: runtime.NumGoroutine(), FDs: len(fds), MockChecks: active.Load(), PeakMockChecks: peak.Load(), Status: status}
		json.NewEncoder(w).Encode(value)
	})
	controlListener, err := net.Listen("tcp", "127.0.0.1:19090")
	if err != nil {
		return err
	}
	api := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go api.Serve(controlListener)
	defer api.Close()
	return daemon.Run(ctx, settings, stateDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

func metrics(ctx context.Context) (resources, error) {
	var value resources
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, control+"/metrics", nil)
	if err != nil {
		return value, err
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return value, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return value, fmt.Errorf("metrics HTTP %d", res.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&value)
	return value, err
}
func setDelay(ctx context.Context, d time.Duration) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, control+"/delay?duration="+d.String(), nil)
	if err != nil {
		return err
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 204 {
		return fmt.Errorf("delay HTTP %d", res.StatusCode)
	}
	return nil
}

type peer struct {
	client *derphttp.Client
	key    key.NodePublic
	ack    chan struct{}
}
type measurement struct {
	samples [1000000]atomic.Uint64
	slow    [60001]atomic.Uint64
	packets atomic.Uint64
	errors  atomic.Uint64
}

func (m *measurement) record(latency time.Duration) {
	us := max(int64(latency/time.Microsecond), 0)
	if us < int64(len(m.samples)) {
		m.samples[us].Add(1)
	} else {
		m.slow[min(us/1000, int64(len(m.slow)-1))].Add(1)
	}
	m.packets.Add(1)
}
func (m *measurement) percentile(fraction float64) int {
	target := max(uint64(1), uint64(float64(m.packets.Load())*fraction))
	if m.packets.Load() == 0 {
		return 0
	}
	var count uint64
	for i := range m.samples {
		count += m.samples[i].Load()
		if count >= target {
			return i
		}
	}
	for i := range m.slow {
		count += m.slow[i].Load()
		if count >= target {
			return i * 1000
		}
	}
	return 0
}

// Runtime status has additional fields in newer revisions. Decode only quota
// fields so the identical fixture can also build against the baseline daemon.
func quotasReleased(status daemon.Status) bool {
	var value struct {
		Connections struct{ Active int }
		Admission   struct{ Requests, Running int }
	}
	b, err := json.Marshal(status)
	if err != nil {
		return false
	}
	if json.Unmarshal(b, &value) != nil {
		return false
	}
	return value.Connections.Active == 0 && value.Admission.Requests == 0 && value.Admission.Running == 0
}

type report struct {
	Samples             uint64    `json:"resource_samples"`
	SamplingErrors      uint64    `json:"sampling_errors"`
	Scenario            string    `json:"scenario"`
	Connections         int       `json:"connections"`
	Seconds             float64   `json:"seconds"`
	Packets             uint64    `json:"packets"`
	Mbps                float64   `json:"mbps"`
	P50                 int       `json:"p50_us"`
	P95                 int       `json:"p95_us"`
	P99                 int       `json:"p99_us"`
	Errors              uint64    `json:"errors"`
	RejectedConnections int       `json:"rejected_connections"`
	Before              resources `json:"before"`
	Loaded              resources `json:"loaded"`
	After               resources `json:"after"`
	PeakRSS             uint64    `json:"peak_rss_bytes"`
	PeakFDs             int       `json:"peak_fds"`
	PeakGoroutines      int       `json:"peak_goroutines"`
	CPUPercent          float64   `json:"cpu_percent"`
	Allocated           uint64    `json:"allocated_bytes"`
	GCs                 uint32    `json:"gc_cycles"`
	GCPause             uint64    `json:"gc_pause_ns"`
}

func connect(ctx context.Context, mon *netmon.Monitor, roots *x509.CertPool) (*peer, error) {
	private := key.NewNode()
	client, err := derphttp.NewClient(private, "https://relay.test/derp", func(string, ...any) {}, mon)
	if err != nil {
		return nil, err
	}
	client.TLSConfig = &tls.Config{RootCAs: roots, ServerName: "relay.test"}
	client.SetURLDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
	})
	attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	stop := context.AfterFunc(attempt, func() { client.Close() })
	defer stop()
	err = client.Connect(attempt)
	if err == nil {
		var msg derp.ReceivedMessage
		msg, err = client.Recv()
		if _, ok := msg.(derp.ServerInfoMessage); err == nil && !ok {
			err = fmt.Errorf("expected server info, got %T", msg)
		}
	}
	if err == nil {
		err = attempt.Err()
	}
	if err != nil {
		client.Close()
		return nil, err
	}
	return &peer{client: client, key: private.Public(), ack: make(chan struct{}, 1)}, nil
}

func connectAll(ctx context.Context, mon *netmon.Monitor, roots *x509.CertPool, n, parallel int, retry bool) ([]*peer, int, error) {
	peers := make([]*peer, n)
	var rejected atomic.Int32
	var wg sync.WaitGroup
	tasks := make(chan int)
	for range min(n, parallel) {
		wg.Go(func() {
			for index := range tasks {
				for attempt := 0; attempt < 8; attempt++ {
					p, err := connect(ctx, mon, roots)
					if err == nil {
						peers[index] = p
						break
					}
					rejected.Add(1)
					if !retry || ctx.Err() != nil {
						break
					}
					timer := time.NewTimer(100 * time.Millisecond)
					select {
					case <-timer.C:
					case <-ctx.Done():
					}
					timer.Stop()
				}
			}
		})
	}
	for i := range n {
		tasks <- i
	}
	close(tasks)
	wg.Wait()
	if retry {
		for _, p := range peers {
			if p == nil {
				closePeers(peers)
				return nil, int(rejected.Load()), errors.New("could not establish all DERP connections")
			}
		}
	}
	return peers, int(rejected.Load()), nil
}
func closePeers(peers []*peer) {
	var wg sync.WaitGroup
	for _, p := range peers {
		if p != nil {
			wg.Go(func() { p.client.Close() })
		}
	}
	wg.Wait()
}

func runClient(parent context.Context, scenario string, n int, duration time.Duration) error {
	if scenario != "forward" && scenario != "idle" && scenario != "slow" && scenario != "reconnect" && scenario != "admission" {
		return errors.New("unknown scenario")
	}
	ctx, cancel := context.WithTimeout(parent, duration+3*time.Minute)
	defer cancel()
	before, err := metrics(ctx)
	if err != nil {
		return err
	}
	if !before.Status.Ready {
		return errors.New("daemon not ready")
	}
	res, err := httpClient.Get(control + "/certificate")
	if err != nil {
		return err
	}
	public, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(public) {
		return errors.New("fixture certificate missing")
	}
	mon := netmon.NewStatic()
	defer mon.Close()
	peers, rejected, err := connectAll(ctx, mon, roots, n, 32, true)
	if err != nil {
		return err
	}
	defer func() { closePeers(peers) }()
	if scenario == "reconnect" {
		closePeers(peers)
		peers, rejected, err = connectAll(ctx, mon, roots, n, 256, true)
		if err != nil {
			return err
		}
	}
	if scenario == "admission" {
		if err = setDelay(ctx, 3500*time.Millisecond); err != nil {
			return err
		}
		faults, failures, e := connectAll(ctx, mon, roots, min(n, 256), 256, false)
		closePeers(faults)
		if e != nil {
			return e
		}
		rejected += failures
		if failures == 0 {
			return errors.New("delayed tailscaled did not reject connections")
		}
		if err = setDelay(ctx, 0); err != nil {
			return err
		}
		recovered, _, e := connectAll(ctx, mon, roots, min(n, 256), 32, true)
		closePeers(recovered)
		if e != nil {
			return fmt.Errorf("admission did not recover: %w", e)
		}
	}
	loaded, err := metrics(ctx)
	if err != nil {
		return err
	}
	result := report{Scenario: scenario, Connections: n, RejectedConnections: rejected, Before: before, Loaded: loaded, PeakRSS: loaded.RSS, PeakFDs: loaded.FDs, PeakGoroutines: loaded.Goroutines}
	measured, stop := context.WithTimeout(ctx, duration)
	defer stop()
	var wg sync.WaitGroup
	var m measurement
	start := time.Now()
	for i, p := range peers {
		wg.Go(func() {
			for measured.Err() == nil {
				msg, err := p.client.Recv()
				if err != nil {
					if measured.Err() == nil {
						m.errors.Add(1)
					}
					return
				}
				if measured.Err() != nil {
					return
				}
				if packet, ok := msg.(derp.ReceivedPacket); ok {
					if len(packet.Data) != payloadSize || packet.Source != peers[i^1].key {
						m.errors.Add(1)
						continue
					}
					m.record(time.Since(time.Unix(0, int64(binary.LittleEndian.Uint64(packet.Data)))))
					select {
					case p.ack <- struct{}{}:
					default:
					}
					if scenario == "slow" && i%2 == 1 {
						timer := time.NewTimer(100 * time.Millisecond)
						select {
						case <-timer.C:
						case <-measured.Done():
						}
						timer.Stop()
					}
				}
			}
		})
	}
	if scenario != "idle" {
		for i := 0; i < n; i += 2 {
			if scenario == "slow" && i >= 64 {
				break
			}
			sender, receiver := peers[i], peers[i+1]
			wg.Go(func() {
				payload := make([]byte, payloadSize)
				var pace *time.Ticker
				if scenario == "slow" {
					pace = time.NewTicker(2 * time.Millisecond)
					defer pace.Stop()
				}
				for measured.Err() == nil {
					binary.LittleEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
					if err := sender.client.Send(receiver.key, payload); err != nil {
						if measured.Err() == nil {
							m.errors.Add(1)
						}
						return
					}
					if pace != nil {
						select {
						case <-pace.C:
						case <-measured.Done():
							return
						}
					} else {
						select {
						case <-receiver.ack:
						case <-measured.Done():
							return
						}
					}
				}
			})
		}
	}
	// Sampling must not control the workload timer or silently truncate it.
	sampleCtx, cancelSamples := context.WithCancel(ctx)
	samples := make(chan resources, 1)
	var samplingErrors, sampleCount atomic.Uint64
	var sampler sync.WaitGroup
	sampler.Go(func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sampleCtx.Done():
				return
			case <-ticker.C:
			}
			request, cancel := context.WithTimeout(sampleCtx, 2*time.Second)
			sample, err := metrics(request)
			cancel()
			if err != nil {
				if sampleCtx.Err() == nil {
					samplingErrors.Add(1)
				}
				continue
			}
			sampleCount.Add(1)
			select {
			case samples <- sample:
			case <-sampleCtx.Done():
				return
			}
		}
	})
collect:
	for {
		select {
		case <-measured.Done():
			break collect
		case sample := <-samples:
			result.PeakRSS = max(result.PeakRSS, sample.MaxRSS, sample.RSS)
			result.PeakFDs = max(result.PeakFDs, sample.FDs)
			result.PeakGoroutines = max(result.PeakGoroutines, sample.Goroutines)
		}
	}
	result.Seconds = time.Since(start).Seconds()
	stop()
	cancelSamples()
	closePeers(peers)
	wg.Wait()
	sampler.Wait()
	result.Samples, result.SamplingErrors = sampleCount.Load(), samplingErrors.Load()

	end, err := metrics(ctx)
	if err != nil {
		return err
	}
	result.PeakRSS = max(result.PeakRSS, end.MaxRSS)
	result.Packets = m.packets.Load()
	result.Errors = m.errors.Load()
	result.Mbps = float64(result.Packets*payloadSize*8) / result.Seconds / 1e6
	result.P50, result.P95, result.P99 = m.percentile(.5), m.percentile(.95), m.percentile(.99)
	result.CPUPercent = (end.CPUSeconds - loaded.CPUSeconds) / result.Seconds * 100
	result.Allocated = end.Allocated - loaded.Allocated
	result.GCs = end.GC - loaded.GC
	result.GCPause = end.GCPause - loaded.GCPause
	// Idle HTTP pools are bounded but intentionally survive bursts for one
	// minute. Wait for their normal expiry before evaluating resource recovery.
	cooldown := time.NewTimer(75 * time.Second)
	defer cooldown.Stop()
	for {
		timer := time.NewTimer(time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		result.After, err = metrics(ctx)
		if err != nil {
			return err
		}
		if result.After.FDs <= before.FDs+16 && result.After.Goroutines <= before.Goroutines+32 && quotasReleased(result.After.Status) {
			break
		}
		select {
		case <-cooldown.C:
			goto cooled
		default:
		}
	}
cooled:

	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if result.Samples == 0 || result.SamplingErrors > max(uint64(1), result.Samples/10) {
		return errors.New("insufficient reliable resource samples")
	}
	if !quotasReleased(result.After.Status) {
		return errors.New("connection or admission quota did not recover")
	}
	if scenario != "slow" && result.Errors > 0 {
		return errors.New("unexpected connection or forwarding failures")
	}
	if scenario != "idle" && result.Packets == 0 {
		return errors.New("no packets forwarded")
	}
	if result.After.FDs > before.FDs+16 || result.After.Goroutines > before.Goroutines+32 {
		return errors.New("connections or background tasks did not recover after cooldown")
	}
	return ctx.Err()
}

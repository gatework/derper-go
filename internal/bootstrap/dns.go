// Package bootstrap serves an explicit cached allowlist for /bootstrap-dns.
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Name struct{ Name, RolloutRecord string }
type Options struct {
	Names    []string
	Unlisted []Name
}
type entry struct {
	Addresses []netip.Addr
	Percent   int
	Updated   time.Time
}
type snapshot struct {
	Public  []byte
	Hidden  map[string]entry
	Entries map[string]entry
}
type Service struct {
	options   Options
	current   atomic.Pointer[snapshot]
	lookupIP  func(context.Context, string, string) ([]netip.Addr, error)
	lookupTXT func(context.Context, string) ([]string, error)
}

func New(options Options) *Service {
	options.Names = append([]string(nil), options.Names...)
	options.Unlisted = append([]Name(nil), options.Unlisted...)
	service := &Service{options: options, lookupIP: net.DefaultResolver.LookupNetIP, lookupTXT: net.DefaultResolver.LookupTXT}
	service.current.Store(&snapshot{Public: []byte("{}\n"), Hidden: map[string]entry{}, Entries: map[string]entry{}})
	return service
}
func (s *Service) Run(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, time.Minute)
		err := s.refresh(attempt)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Service) refresh(ctx context.Context) error {
	names := make([]Name, 0, len(s.options.Names)+len(s.options.Unlisted))
	for _, name := range s.options.Names {
		names = append(names, Name{Name: name})
	}
	names = append(names, s.options.Unlisted...)
	old := s.current.Load()
	entries := make(map[string]entry, len(names))
	var mu sync.Mutex
	var failures []error
	tasks := make(chan Name)
	var workers sync.WaitGroup
	for range min(4, len(names)) {
		workers.Go(func() {
			for name := range tasks {
				value := entry{Percent: 100, Updated: time.Now()}
				addresses, err := s.lookupIP(ctx, "ip", name.Name)
				if err == nil && len(addresses) == 0 {
					err = errors.New("no addresses")
				}
				if err == nil {
					value.Addresses = append([]netip.Addr(nil), addresses...)
				} else if previous, ok := old.Entries[name.Name]; ok && time.Since(previous.Updated) < time.Hour {
					value = previous
				}
				if name.RolloutRecord != "" {
					values, lookupErr := s.lookupTXT(ctx, name.RolloutRecord)
					value.Percent = rollout(values)
					if lookupErr != nil {
						err = errors.Join(err, lookupErr)
					}
				}
				mu.Lock()
				entries[name.Name] = value
				if err != nil {
					failures = append(failures, fmt.Errorf("bootstrap DNS %s: %w", name.Name, err))
				}
				mu.Unlock()
			}
		})
	}
	for _, name := range names {
		select {
		case tasks <- name:
		case <-ctx.Done():
			close(tasks)
			workers.Wait()
			return ctx.Err()
		}
	}
	close(tasks)
	workers.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	published := make(map[string][]netip.Addr, len(s.options.Names))
	for _, name := range s.options.Names {
		if len(entries[name].Addresses) > 0 {
			published[name] = entries[name].Addresses
		}
	}
	body, err := json.Marshal(published)
	if err != nil {
		return err
	}
	hidden := make(map[string]entry, len(s.options.Unlisted))
	for _, name := range s.options.Unlisted {
		hidden[name.Name] = entries[name.Name]
	}
	s.current.Store(&snapshot{Public: append(body, '\n'), Hidden: hidden, Entries: entries})
	return errors.Join(failures...)
}

// Ambiguous, missing or invalid TXT percentages refuse the hidden response.
func rollout(values []string) int {
	if len(values) != 1 {
		return 0
	}
	value, err := strconv.Atoi(values[0])
	if err != nil || value < 0 || value > 100 {
		return 0
	}
	return value
}
func matches(remote string, percent int) bool {
	if percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	hash := sha256.Sum256([]byte(ip.Unmap().String()))
	return binary.BigEndian.Uint64(hash[:8])%100 < uint64(percent)
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	value := s.current.Load()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Connection", "close")
	query := strings.ToLower(strings.TrimSuffix(r.URL.Query().Get("q"), "."))
	if hidden, ok := value.Hidden[query]; ok && len(hidden.Addresses) > 0 && matches(r.RemoteAddr, hidden.Percent) {
		_ = json.NewEncoder(w).Encode(map[string][]netip.Addr{query: hidden.Addresses})
		return
	}
	_, _ = w.Write(value.Public)
}

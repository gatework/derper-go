package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/testutil"
)

func TestStaleStatusNeverClaimsReadiness(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Status{PID: os.Getpid(), Process: identity, Active: true, Ready: true, Updated: time.Now()}
	if err = state.WriteJSON(filepath.Join(dir, "status.json"), snapshot); err != nil {
		t.Fatal(err)
	}
	s, err := ReadStatus(dir)
	if err != nil || !s.Active || !s.Ready {
		t.Fatal(s, err)
	}
	store.Close()
	s, err = ReadStatus(dir)
	if err != nil || s.Active || s.Ready {
		t.Fatal("stale readiness", s, err)
	}
	store, err = state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot.Process = "previous-boot:reused-pid"
	if err = state.WriteJSON(filepath.Join(dir, "status.json"), snapshot); err != nil {
		t.Fatal(err)
	}
	s, err = ReadStatus(dir)
	if err != nil || s.Active {
		t.Fatal("PID reuse accepted", s, err)
	}
}
func TestDaemonReadyBeforeDNSFailureAndNotify(t *testing.T) {
	cert := testutil.Cert(t, "relay.example.com", 1)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, cert.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	// A short Unix path avoids the 108-byte sockaddr limit on CI.
	notifyDir, err := os.MkdirTemp("", "dgn-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(notifyDir)
	socket := filepath.Join(notifyDir, "notify")
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notify.Close()
	t.Setenv("NOTIFY_SOCKET", socket)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	s := config.Settings{Domain: "relay.example.com", Port: port, Region: 900, Access: config.Public, CertificateFile: certPath, CertificateKey: keyPath, PublishDNS: true, TokenFile: filepath.Join(dir, "missing-token")}
	s.IPv4, _ = config.Address("192.0.2.1", true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, s, filepath.Join(dir, "state"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	notify.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b [1024]byte
	n, _, err := notify.ReadFromUnix(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if n < 7 || string(b[:7]) != "READY=1" {
		t.Fatalf("notify %q", b[:n])
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, e := ReadStatus(filepath.Join(dir, "state"))
		if e == nil && status.DNS.State == "degraded" {
			if !status.Active || !status.Ready {
				t.Fatal("DNS failure killed relay", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS failure not reported", status, e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{RootCAs: cert.Roots, ServerName: s.Domain})
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown blocked")
	}
	status, err := ReadStatus(filepath.Join(dir, "state"))
	if err != nil || status.Active || status.Ready {
		t.Fatal("shutdown status", status, err)
	}
}

func TestStartupHeartbeatAndWriteRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var writes int
		var saved Status
		fail := true
		h := &health{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), status: Status{Active: true}, dirty: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{}), write: func(_ string, v any) error {
			writes++
			if fail {
				return errors.New("disk unavailable")
			}
			saved = v.(Status)
			return nil
		}}
		go h.publish()
		synctest.Wait()
		time.Sleep(35 * time.Second)
		synctest.Wait()
		if writes != 3 {
			t.Fatal("missing startup heartbeats", writes)
		}
		fail = false
		h.dns(nil)
		synctest.Wait()
		if saved.Phase != "starting" || saved.Ready || !saved.Active || saved.Updated.IsZero() {
			t.Fatal("incorrect startup state", saved)
		}
		h.stop(nil)
		if saved.Phase != "stopped" || saved.Active {
			t.Fatal("shutdown was not flushed", saved)
		}
	})
}

func TestSlowStatusWriteDoesNotHoldHealthLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		h := &health{logger: slog.Default(), dirty: make(chan struct{}, 1), write: func(string, any) error { close(entered); <-release; return nil }}
		done := make(chan struct{})
		go func() { _ = h.save(); close(done) }()
		<-entered
		h.dns(errors.New("maintenance failure"))
		if h.snapshot().DNS.State != "degraded" {
			t.Fatal("blocked state update")
		}
		close(release)
		<-done
	})
}

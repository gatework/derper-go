package relay

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gatework/derper-go/internal/testutil"
	"tailscale.com/derp"
	"tailscale.com/types/key"
)

func TestConnectionQuotaReleasedExactlyOnce(t *testing.T) {
	quota := &connectionLimit{limit: 1}
	if !quota.acquire() || quota.acquire() {
		t.Fatal("limit not enforced")
	}
	a, b := net.Pipe()
	defer b.Close()
	conn := &limitedConn{Conn: a, limit: quota}
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() { _ = conn.Close() })
	}
	wg.Wait()
	if quota.stats().Active != 0 || !quota.acquire() {
		t.Fatal("quota not released exactly once", quota.stats())
	}
}

func TestConnectionLimitIncludesHijackedDERP(t *testing.T) {
	cert := testutil.Cert(t, "relay.example.com", 1)
	opts := relayConfig()
	opts.MaxConnections = 1
	s, cancel, done := start(t, opts, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert.Pair, nil })
	c := client(t, s, key.NewNode(), cert)
	if message, err := receive(t, c); err != nil {
		t.Fatal(err)
	} else if _, ok := message.(derp.ServerInfoMessage); !ok {
		t.Fatal(message)
	}
	rejected, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = rejected.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, err = rejected.Read(buf[:]); err != io.EOF {
		t.Fatal("excess connection not closed", err)
	}
	rejected.Close()
	if stats := s.Connections(); stats.Active != 1 || stats.Rejected != 1 {
		t.Fatal("hijacked connection lost quota", stats)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if s.Connections().Active != 0 {
		t.Fatal("shutdown retained connection quota", s.Connections())
	}
}

func BenchmarkConnectionQuota(b *testing.B) {
	quota := &connectionLimit{limit: 2048}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if quota.acquire() {
				quota.active.Add(-1)
			}
		}
	})
}

func TestConnectionBurstAndRateRefill(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		quota := &connectionLimit{limit: 100}
		quota.setRate(2, 2)
		first, second, third := quota.acquire(), quota.acquire(), quota.acquire()
		if !first || !second || third {
			t.Fatal("burst policy")
		}
		time.Sleep(500 * time.Millisecond)
		if !quota.acquire() {
			t.Fatal("rate did not refill")
		}
		if s := quota.stats(); s.Accepted != 3 || s.RateRejected != 1 || s.Rejected != 1 {
			t.Fatal(s)
		}
	})
}

func TestReloadDoesNotGrantAnotherBurstOrEvictConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		quota := &connectionLimit{limit: 8}
		quota.setRate(1, 2)
		first, second := quota.acquire(), quota.acquire()
		if !first || !second {
			t.Fatal("initial burst rejected")
		}
		quota.update(1, 1, 2)
		if quota.acquire() || quota.stats().Active != 2 {
			t.Fatal("reload evicted or ignored limit")
		}
		quota.update(8, 1, 2)
		if quota.acquire() {
			t.Fatal("reload reset the token balance")
		}
		time.Sleep(time.Second)
		if !quota.acquire() {
			t.Fatal("rate did not refill after reload")
		}
	})
}

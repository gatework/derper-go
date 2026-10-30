package relay

import (
	"net"
	"sync"
	"sync/atomic"
)

const DefaultMaxConnections = 2048

type ConnectionStats struct {
	Active   int64  `json:"active"`
	Limit    int64  `json:"limit"`
	Accepted uint64 `json:"accepted"`
	Rejected uint64 `json:"rejected"`
}

type connectionLimit struct {
	limit              int64
	active             atomic.Int64
	accepted, rejected atomic.Uint64
}

func (l *connectionLimit) stats() ConnectionStats {
	return ConnectionStats{Active: l.active.Load(), Limit: l.limit, Accepted: l.accepted.Load(), Rejected: l.rejected.Load()}
}
func (l *connectionLimit) acquire() bool {
	for {
		n := l.active.Load()
		if n >= l.limit {
			l.rejected.Add(1)
			return false
		}
		if l.active.CompareAndSwap(n, n+1) {
			l.accepted.Add(1)
			return true
		}
	}
}

type limitedListener struct {
	net.Listener
	limit *connectionLimit
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.limit.acquire() {
			return &limitedConn{Conn: conn, limit: l.limit}, nil
		}
		_ = conn.Close()
	}
}

// The underlying connection carries the quota across TLS and HTTP hijacking.
// net/http and the upstream DERP owner can both Close it; release exactly once.
type limitedConn struct {
	net.Conn
	limit *connectionLimit
	once  sync.Once
	err   error
}

func (c *limitedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.limit.active.Add(-1) })
	return c.err
}

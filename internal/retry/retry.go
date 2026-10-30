// Package retry contains bounded scheduling arithmetic shared by maintenance tasks.
package retry

import (
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Next doubles a positive backoff without overflowing.
func Next(current, limit time.Duration) time.Duration {
	if current >= limit/2 {
		return limit
	}
	return min(limit, max(time.Nanosecond, current*2))
}

// Jitter only adds delay: a provider's not-before time is never shortened.
func Jitter(delay time.Duration) time.Duration {
	delay = max(0, delay)
	room := min(delay/10, time.Duration(math.MaxInt64)-delay)
	if room == 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(int64(room)+1))
}

// After parses Retry-After at a supplied instant. Unrepresentably long positive
// delays saturate instead of wrapping or causing an immediate retry.
func After(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header != "" && strings.IndexFunc(header, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
		seconds, err := strconv.ParseUint(header, 10, 64)
		if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
			return time.Duration(math.MaxInt64)
		}
		return time.Duration(seconds) * time.Second
	}
	if until, err := http.ParseTime(header); err == nil {
		return max(0, until.Sub(now))
	}
	return 0
}

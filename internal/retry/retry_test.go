package retry

import (
	"math"
	"testing"
	"time"
)

func TestSchedulingNeverOverflowsOrRetriesEarly(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	for _, raw := range []string{"9223372036854775807", "999999999999999999999999999999", "Fri, 31 Dec 9999 23:59:59 GMT"} {
		d := After(raw, now)
		if d != time.Duration(math.MaxInt64) || Jitter(d) < d {
			t.Fatalf("%s: %v", raw, d)
		}
	}
	for _, raw := range []string{"", "-1", "not-a-date"} {
		if After(raw, now) != 0 {
			t.Fatal(raw)
		}
	}
	if After(" 120 ", now) != 2*time.Minute {
		t.Fatal("seconds")
	}
	if Next(time.Duration(math.MaxInt64)-1, time.Duration(math.MaxInt64)) != time.Duration(math.MaxInt64) {
		t.Fatal("backoff overflow")
	}
	for range 100 {
		if d := Jitter(time.Minute); d < time.Minute || d > 66*time.Second {
			t.Fatal(d)
		}
	}
}

func FuzzAfter(f *testing.F) {
	for _, raw := range []string{"120", "-1", "999999999999999999999999999", "Fri, 31 Dec 9999 23:59:59 GMT"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		delay := After(raw, time.Unix(0, 0))
		if delay < 0 || Jitter(delay) < delay {
			t.Fatal("negative or shortened retry", delay)
		}
	})
}

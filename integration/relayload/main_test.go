package main

import (
	"testing"
	"time"
)

func TestLatencyQuantilesKeepLongBackpressureDelays(t *testing.T) {
	var m measurement
	for range 98 {
		m.record(1500 * time.Microsecond)
	}
	m.record(2 * time.Second)
	m.record(3 * time.Second)
	if p50, p99 := m.percentile(.5), m.percentile(.99); p50 != 1500 || p99 != 2000000 {
		t.Fatalf("p50=%dµs p99=%dµs", p50, p99)
	}
}

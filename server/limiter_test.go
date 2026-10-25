package server

import (
	"testing"
	"time"
)

func TestTheBucketLimitsABurstAndRefills(t *testing.T) {
	now := time.Now()
	l := newLimiters(100, 200)
	ok := 0
	for i := 0; i < 1000; i++ {
		if l.allow("k", now) {
			ok++
		}
	}
	if ok != 200 {
		t.Fatalf("a burst let %d through, want 200", ok)
	}
	if l.allow("other", now) != true {
		t.Fatal("another key shares the bucket")
	}
	now = now.Add(time.Second)
	ok = 0
	for i := 0; i < 1000; i++ {
		if l.allow("k", now) {
			ok++
		}
	}
	if ok < 99 || ok > 101 {
		t.Fatalf("a second refilled %d", ok)
	}
	l.sweep(now.Add(time.Hour), time.Minute)
	if len(l.shards[fnv32("k")%32].m) != 0 {
		t.Fatal("idle buckets were kept")
	}
}

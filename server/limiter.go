package server

import (
	"sync"
	"time"
)

// bucket is a token bucket: rate tokens a second, up to burst saved.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
	used   time.Time
}

func newBucket(rate, burst float64, now time.Time) *bucket {
	return &bucket{tokens: burst, last: now, rate: rate, burst: burst, used: now}
}

func (b *bucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last, b.used = now, now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limiters hands out one bucket per key. Keys are split over shards so callers
// with different keys do not share a lock, and idle buckets are dropped.
type limiters struct {
	rate, burst float64
	shards      [32]struct {
		mu sync.Mutex
		m  map[string]*bucket
	}
}

func newLimiters(rate, burst float64) *limiters {
	l := &limiters{rate: rate, burst: burst}
	for i := range l.shards {
		l.shards[i].m = map[string]*bucket{}
	}
	return l
}

func (l *limiters) allow(key string, now time.Time) bool {
	if l.rate <= 0 {
		return true
	}
	sh := &l.shards[fnv32(key)%uint32(len(l.shards))]
	sh.mu.Lock()
	b := sh.m[key]
	if b == nil {
		b = newBucket(l.rate, l.burst, now)
		sh.m[key] = b
	}
	sh.mu.Unlock()
	return b.allow(now)
}

// sweep forgets buckets not used for idle.
func (l *limiters) sweep(now time.Time, idle time.Duration) {
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, b := range sh.m {
			b.mu.Lock()
			old := now.Sub(b.used) > idle
			b.mu.Unlock()
			if old {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

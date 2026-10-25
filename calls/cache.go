package calls

import (
	"hash/fnv"
	"sync"
	"time"
)

// cache keeps recently read calls in memory so the relay paths (signals, key
// messages, SFU preconditions), which only need to know who is in a call, never
// touch the database. It is split into shards so that lookups for different
// calls do not share a lock.
//
// Entries hold a Call whose participant slice is never modified in place:
// every change drops the entry and the next read replaces it.
type cache struct {
	ttl    time.Duration
	now    func() time.Time
	shards [cacheShards]cacheShard
}

const (
	cacheShards   = 64
	maxPerShard   = 2048
	evictFraction = 2
)

type cacheShard struct {
	mu sync.RWMutex
	m  map[string]cacheEntry
}

type cacheEntry struct {
	c  Call
	at time.Time
}

func newCache(ttl time.Duration, now func() time.Time) *cache {
	c := &cache{ttl: ttl, now: now}
	for i := range c.shards {
		c.shards[i].m = map[string]cacheEntry{}
	}
	return c
}

func (c *cache) shard(id string) *cacheShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return &c.shards[h.Sum32()%cacheShards]
}

func (c *cache) get(id string) (Call, bool) {
	sh := c.shard(id)
	sh.mu.RLock()
	e, ok := sh.m[id]
	sh.mu.RUnlock()
	if !ok || c.now().Sub(e.at) > c.ttl {
		return Call{}, false
	}
	return e.c, true
}

func (c *cache) put(call Call) {
	sh := c.shard(call.ID)
	now := c.now()
	sh.mu.Lock()
	if len(sh.m) >= maxPerShard {
		// Make room: drop what has expired, and if that is not enough, about half
		// of what is left. Calls are cheap to read again.
		for k, e := range sh.m {
			if now.Sub(e.at) > c.ttl {
				delete(sh.m, k)
			}
		}
		for k := range sh.m {
			if len(sh.m) < maxPerShard/evictFraction {
				break
			}
			delete(sh.m, k)
		}
	}
	sh.m[call.ID] = cacheEntry{c: call, at: now}
	sh.mu.Unlock()
}

func (c *cache) drop(id string) {
	sh := c.shard(id)
	sh.mu.Lock()
	delete(sh.m, id)
	sh.mu.Unlock()
}

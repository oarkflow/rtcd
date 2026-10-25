package server_test

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarkflow/rtcd/server"
)

// TestRelayThroughputAndLatencyAsUsersGrow measures the relay path: key and
// signaling messages between people in calls, over real WebSockets. Each pair
// sends as fast as the service acknowledges. It prints what it measures.
func TestRelayThroughputAndLatencyAsUsersGrow(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	type result struct {
		pairs      int
		msgsPerSec float64
		p50, p99   time.Duration
		delivered  int64
	}
	var results []result
	for _, pairs := range []int{1, 10, 100, 400} {
		s := start(t, func(c *server.Config) {
			c.OpsPerSecond, c.OpsBurst = 1e9, 1e9
			c.RelayPerSecond, c.RelayBurst = 1e9, 1e9
			c.MaxConnections = 5000
		})
		type pair struct {
			a, b *peer
			call string
		}
		ps := make([]pair, pairs)
		var setup sync.WaitGroup
		for i := range ps {
			setup.Add(1)
			go func(i int) {
				defer setup.Done()
				a, b := s.dial(s.acme, fmt.Sprintf("a%d", i)), s.dial(s.acme, fmt.Sprintf("b%d", i))
				var st startReply
				a.must("call.start", map[string]any{"to": []string{b.user}}, &st)
				b.next("call.incoming")
				b.must("call.answer", map[string]any{"call": st.Call.ID}, nil)
				ps[i] = pair{a, b, st.Call.ID}
			}(i)
		}
		setup.Wait()

		const each = 300
		var delivered atomic.Int64
		var mu sync.Mutex
		var lats []time.Duration
		var wg sync.WaitGroup
		started := time.Now()
		for _, p := range ps {
			wg.Add(2)
			go func(p pair) { // the receiver drains what is pushed to it
				defer wg.Done()
				for n := 0; n < each; n++ {
					select {
					case _, ok := <-p.b.Events():
						if !ok {
							return
						}
						delivered.Add(1)
					case <-time.After(20 * time.Second):
						t.Errorf("%s stopped hearing messages after %d", p.b.user, n)
						return
					}
				}
			}(p)
			go func(p pair) {
				defer wg.Done()
				mine := make([]time.Duration, 0, each)
				for n := 0; n < each; n++ {
					t0 := time.Now()
					if err := p.a.call("call.e2ee", map[string]any{"call": p.call, "to": p.b.user, "data": "0123456789abcdef0123456789abcdef0123456789abcdef"}, nil); err != nil {
						t.Errorf("%v", err)
						return
					}
					mine = append(mine, time.Since(t0))
				}
				mu.Lock()
				lats = append(lats, mine...)
				mu.Unlock()
			}(p)
		}
		wg.Wait()
		elapsed := time.Since(started)
		sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
		if len(lats) == 0 {
			t.Fatal("nothing was sent")
		}
		au := s.srv.Audit.Stats()
		drainStart := time.Now()
		ctx, cancel := contextTimeout(60 * time.Second)
		_ = s.srv.Audit.Flush(ctx)
		cancel()
		t.Logf("%d pairs: audit queued %d, written when traffic stopped %d, waiting %d, refused %d; the writer then needed %v to catch up", pairs, au.Queued, au.Written, au.Waiting, au.Refused, time.Since(drainStart).Round(time.Millisecond))
		r := result{pairs: pairs, msgsPerSec: float64(len(lats)) / elapsed.Seconds(), p50: lats[len(lats)/2], p99: lats[len(lats)*99/100], delivered: delivered.Load()}
		results = append(results, r)
		if int(r.delivered) != pairs*each {
			t.Errorf("%d pairs: %d of %d messages were delivered", pairs, r.delivered, pairs*each)
		}
	}
	t.Logf("%d CPUs, %d goroutines of sending, real WebSockets over loopback, relay of a 48-byte key message", runtime.NumCPU(), runtime.GOMAXPROCS(0))
	for _, r := range results {
		t.Logf("%4d pairs (%4d sockets): %8.0f messages/s   ack latency p50 %-10v p99 %-10v", r.pairs, r.pairs*2, r.msgsPerSec, r.p50, r.p99)
	}
	last := results[len(results)-1]
	if last.p99 > 2*time.Second {
		t.Fatalf("with %d pairs the 99th percentile is %v", last.pairs, last.p99)
	}
}

// TestACallIsNotSlowedByAnAuditStoreThatIsStalled holds the audit database's
// write lock, as a long backup or a failing disk would, and checks that calls go
// on at full speed while the audit queue absorbs the entries.
func TestACallIsNotSlowedByAnAuditStoreThatIsStalled(t *testing.T) {
	s := start(t, func(c *server.Config) {
		c.OpsPerSecond, c.OpsBurst = 1e9, 1e9
		c.RelayPerSecond, c.RelayBurst = 1e9, 1e9
	})
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	var st startReply
	ada.must("call.start", map[string]any{"to": []string{"bob"}}, &st)
	bob.next("call.incoming")
	bob.must("call.answer", map[string]any{"call": st.Call.ID}, nil)
	measure := func(n int) (worst time.Duration, total time.Duration) {
		for i := 0; i < n; i++ {
			t0 := time.Now()
			if err := ada.call("call.e2ee", map[string]any{"call": st.Call.ID, "to": "bob", "data": "k"}, nil); err != nil {
				t.Fatal(err)
			}
			d := time.Since(t0)
			total += d
			if d > worst {
				worst = d
			}
		}
		return
	}
	_, base := measure(500)
	// Stall the audit store: another connection takes the write lock and keeps it.
	hold := auditHold(t, s)
	defer hold()
	_, stalled := measure(500)
	waiting := s.srv.Audit.Stats().Waiting
	t.Logf("500 relays: %v with a healthy audit store, %v with it stalled (%d entries queued behind it)", base, stalled, waiting)
	if stalled > base*4+50*time.Millisecond {
		t.Fatalf("calls slowed from %v to %v when the audit store stalled", base, stalled)
	}
	if waiting < 400 {
		t.Fatalf("only %d entries queued: the stall did not take effect", waiting)
	}
}

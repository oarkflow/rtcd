package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/oarkflow/rtcd/server"
)

// BenchmarkRelayOperation is the server's whole cost of relaying one key message,
// without the network: rate limits, the call lookup (from memory), the delivery
// and the audit entry. Each parallel worker has its own call, as separate calls
// on a busy service would. If the path had a shared lock, ns/op would grow with
// -cpu instead of shrinking.
//
//	go test -run xxx -bench RelayOperation -cpu 1,2,4,8,10 ./server
func BenchmarkRelayOperation(b *testing.B) {
	s := startB(b, func(c *server.Config) {
		c.OpsPerSecond, c.OpsBurst = 1e12, 1e12
		c.RelayPerSecond, c.RelayBurst = 1e12, 1e12
		c.AuditQueue = 4 << 20 // room for the whole run, so the benchmark measures the request path and not the sink
	})
	const calls = 512
	ids := make([]string, calls)
	for i := range ids {
		a, bb := fmt.Sprintf("a%d", i), fmt.Sprintf("b%d", i)
		c, err := s.acme.As(a).Start(context.Background(), clientStart(bb))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := s.acme.As(bb).Answer(context.Background(), c.Call.ID); err != nil {
			b.Fatal(err)
		}
		ids[i] = c.Call.ID
	}
	var next atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := int(next.Add(1)-1) % calls
		in, _ := json.Marshal(map[string]any{"call": ids[i], "to": fmt.Sprintf("b%d", i), "data": "0123456789abcdef0123456789abcdef0123456789abcdef"})
		user := fmt.Sprintf("a%d", i)
		for pb.Next() {
			if err := s.srv.ExecForBenchmark(user, "acme", "call.e2ee", in); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

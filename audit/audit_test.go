package audit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var bg = context.Background()

func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { db.Close() })
	return db
}

func newLog(t *testing.T, mod func(*Config)) (*Log, *sql.DB) {
	t.Helper()
	db := openDB(t, filepath.Join(t.TempDir(), "a.db"))
	cfg := Config{DB: db, Dialect: "sqlite", Flush: 5 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	l, err := Open(bg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, db
}

func rec(t *testing.T, l *Log, e Event) {
	t.Helper()
	if err := l.Record(e); err != nil {
		t.Fatal(err)
	}
}

func flush(t *testing.T, l *Log) {
	t.Helper()
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEntriesAreStoredInOrderAndChained(t *testing.T) {
	l, _ := newLog(t, nil)
	for i := 0; i < 5; i++ {
		rec(t, l, Event{Tenant: "acme", Actor: "ada", Action: "call.start", Target: fmt.Sprint("call_", i), Outcome: OK, IP: "10.0.0.1", Transport: "ws", Meta: map[string]any{"invitees": 2}})
	}
	flush(t, l)
	got, err := l.Query(bg, "acme", Filter{})
	if err != nil || len(got) != 5 {
		t.Fatalf("%d %v", len(got), err)
	}
	for i, e := range got {
		if e.Seq != uint64(i+1) || e.Actor != "ada" || e.Meta["invitees"] != float64(2) || e.IP != "10.0.0.1" {
			t.Fatalf("%d: %+v", i, e)
		}
		if i > 0 && e.Prev != got[i-1].Hash {
			t.Fatalf("entry %d does not link to the one before", e.Seq)
		}
	}
	if got[0].Prev != strings.Repeat("0", 64) {
		t.Fatalf("the first entry's prev: %s", got[0].Prev)
	}
	v, err := l.Verify(bg, "acme", 0, 0)
	if err != nil || !v.OK || v.Checked != 5 || v.LastSeq != 5 {
		t.Fatalf("%+v %v", v, err)
	}
	seq, hash, _ := l.Head(bg, "acme")
	if seq != 5 || hash != got[4].Hash {
		t.Fatalf("head %d %s", seq, hash)
	}
}

func TestTenantsHaveSeparateChainsAndNeverSeeEachOther(t *testing.T) {
	l, _ := newLog(t, nil)
	for i := 0; i < 3; i++ {
		rec(t, l, Event{Tenant: "acme", Actor: "ada", Action: "call.start", Outcome: OK})
		rec(t, l, Event{Tenant: "zeta", Actor: "ada", Action: "call.end", Outcome: OK})
	}
	rec(t, l, Event{Action: "auth.failed", Outcome: Denied, Code: "unauthenticated", IP: "203.0.113.9"})
	flush(t, l)
	a, _ := l.Query(bg, "acme", Filter{})
	z, _ := l.Query(bg, "zeta", Filter{})
	if len(a) != 3 || len(z) != 3 {
		t.Fatalf("%d %d", len(a), len(z))
	}
	for _, e := range a {
		if e.Tenant != "acme" || e.Action != "call.start" {
			t.Fatalf("acme saw %+v", e)
		}
	}
	for _, e := range z {
		if e.Seq > 3 {
			t.Fatalf("zeta's sequence is not its own: %+v", e)
		}
	}
	none, _ := l.Query(bg, NoTenant, Filter{})
	if len(none) != 1 || none[0].Action != "auth.failed" || none[0].IP != "203.0.113.9" {
		t.Fatalf("%+v", none)
	}
	if _, err := l.Query(bg, "", Filter{}); err == nil {
		t.Fatal("a query without a tenant was allowed")
	}
}

func TestFiltersAndPaging(t *testing.T) {
	l, _ := newLog(t, nil)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	acts := []struct{ actor, action, target, outcome string }{
		{"ada", "call.start", "c1", OK}, {"bob", "call.answer", "c1", OK}, {"ada", "sfu.join", "c1", OK},
		{"eve", "call.end", "c1", Denied}, {"ada", "group.create", "g1", OK}, {"bob", "group.add", "g1", Failed},
	}
	for i, a := range acts {
		rec(t, l, Event{Tenant: "t", Time: base.Add(time.Duration(i) * time.Minute), Actor: a.actor, Action: a.action, Target: a.target, Outcome: a.outcome})
	}
	flush(t, l)
	count := func(f Filter) int {
		got, err := l.Query(bg, "t", f)
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	cases := map[string]struct {
		f    Filter
		want int
	}{
		"actor":         {Filter{Actor: "ada"}, 3},
		"target":        {Filter{Target: "c1"}, 4},
		"outcome":       {Filter{Outcome: Denied}, 1},
		"exact action":  {Filter{Action: "call.start"}, 1},
		"action prefix": {Filter{Action: "call."}, 3},
		"group prefix":  {Filter{Action: "group."}, 2},
		"time range":    {Filter{From: base.Add(2 * time.Minute), To: base.Add(4 * time.Minute)}, 2},
		"combined":      {Filter{Actor: "ada", Action: "call."}, 1},
		"after seq":     {Filter{AfterSeq: 4}, 2},
		"limit":         {Filter{Limit: 2}, 2},
		"nothing":       {Filter{Actor: "nobody"}, 0},
	}
	for name, c := range cases {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	newest, _ := l.Query(bg, "t", Filter{Newest: true, Limit: 2})
	if len(newest) != 2 || newest[0].Seq != 6 || newest[1].Seq != 5 {
		t.Fatalf("%+v", newest)
	}
	older, _ := l.Query(bg, "t", Filter{Newest: true, Limit: 2, AfterSeq: 5})
	if len(older) != 2 || older[0].Seq != 4 {
		t.Fatalf("paging back: %+v", older)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]string{
		"an entry is edited":       `UPDATE rtc_audit SET actor = 'mallory' WHERE tenant = 't' AND seq = 3`,
		"an outcome is rewritten":  `UPDATE rtc_audit SET outcome = 'ok' WHERE tenant = 't' AND seq = 4`,
		"an entry is deleted":      `DELETE FROM rtc_audit WHERE tenant = 't' AND seq = 3`,
		"the meta is changed":      `UPDATE rtc_audit SET meta = '{"x":1}' WHERE tenant = 't' AND seq = 2`,
		"the time is changed":      `UPDATE rtc_audit SET ts = '2020-01-01T00:00:00.000000000Z' WHERE tenant = 't' AND seq = 5`,
		"a link is rewritten":      `UPDATE rtc_audit SET prev = '` + strings.Repeat("a", 64) + `' WHERE tenant = 't' AND seq = 4`,
		"the first entry vanishes": `DELETE FROM rtc_audit WHERE tenant = 't' AND seq = 1`,
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			l, db := newLog(t, nil)
			for i := 0; i < 6; i++ {
				rec(t, l, Event{Tenant: "t", Actor: "ada", Action: "call.start", Outcome: Denied, Meta: map[string]any{"i": i}})
			}
			flush(t, l)
			if v, _ := l.Verify(bg, "t", 0, 0); !v.OK {
				t.Fatalf("a good chain failed: %+v", v)
			}
			if _, err := db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			v, err := l.Verify(bg, "t", 0, 0)
			if err != nil || v.OK || v.BadSeq == 0 || v.Reason == "" {
				t.Fatalf("tampering went unnoticed: %+v %v", v, err)
			}
		})
	}
}

func TestACutOffTailIsNotDetectedFromInsideButTheHeadGivesItAway(t *testing.T) {
	l, db := newLog(t, nil)
	for i := 0; i < 4; i++ {
		rec(t, l, Event{Tenant: "t", Action: "x", Outcome: OK})
	}
	flush(t, l)
	seq, hash, _ := l.Head(bg, "t")
	_, _ = db.Exec(`DELETE FROM rtc_audit WHERE tenant = 't' AND seq > 2`)
	if v, _ := l.Verify(bg, "t", 0, 0); !v.OK {
		t.Fatal("a shorter chain is still a valid chain")
	}
	// ... which is why the head must be kept elsewhere.
	nseq, nhash, _ := l.Head(bg, "t")
	if nseq == seq || nhash == hash {
		t.Fatal("the head did not change when the tail was cut")
	}
}

func TestConcurrentWritersLoseNothingAndKeepTheChain(t *testing.T) {
	l, _ := newLog(t, func(c *Config) { c.Batch = 64 })
	const writers, each = 16, 400
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				tenant := []string{"a", "b", "c"}[(w+i)%3]
				if err := l.Record(Event{Tenant: tenant, Actor: fmt.Sprint("u", w), Action: "call.e2ee", Outcome: OK, Meta: map[string]any{"i": i}}); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	flush(t, l)
	total := 0
	for _, tn := range []string{"a", "b", "c"} {
		v, err := l.Verify(bg, tn, 0, 0)
		if err != nil || !v.OK {
			t.Fatalf("%s: %+v %v", tn, v, err)
		}
		total += int(v.Checked)
	}
	if total != writers*each {
		t.Fatalf("%d entries stored, %d recorded", total, writers*each)
	}
	if st := l.Stats(); st.Written != int64(total) || st.Refused != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestTheChainContinuesAfterARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	db := openDB(t, path)
	l, _ := Open(bg, Config{DB: db, Dialect: "sqlite", Flush: 5 * time.Millisecond})
	for i := 0; i < 3; i++ {
		rec(t, l, Event{Tenant: "t", Action: "x", Outcome: OK})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := Open(bg, Config{DB: db, Dialect: "sqlite", Flush: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	for i := 0; i < 3; i++ {
		rec(t, l2, Event{Tenant: "t", Action: "y", Outcome: OK})
	}
	flush(t, l2)
	v, _ := l2.Verify(bg, "t", 0, 0)
	if !v.OK || v.Checked != 6 || v.LastSeq != 6 {
		t.Fatalf("%+v", v)
	}
	// Verifying can start part-way through.
	if v, _ := l2.Verify(bg, "t", 4, 0); !v.OK || v.Checked != 2 {
		t.Fatalf("%+v", v)
	}
	if v, _ := l2.Verify(bg, "t", 99, 0); v.OK {
		t.Fatalf("started after an entry that does not exist: %+v", v)
	}
}

func TestClosingStoresWhatIsQueued(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	db := openDB(t, path)
	l, _ := Open(bg, Config{DB: db, Dialect: "sqlite", Flush: time.Hour}) // would never flush by itself
	for i := 0; i < 50; i++ {
		rec(t, l, Event{Tenant: "t", Action: "x", Outcome: OK})
	}
	_ = l.Close()
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM rtc_audit`).Scan(&n)
	if n != 50 {
		t.Fatalf("%d of 50 stored at close", n)
	}
	if err := l.Record(Event{Tenant: "t", Action: "late"}); err != ErrClosed {
		t.Fatalf("recording after close: %v", err)
	}
}

func TestAStalledStoreSlowsRecordersButNeverHangsThemAndNothingAcceptedIsLost(t *testing.T) {
	var mu sync.Mutex
	failing := true
	db := openDB(t, filepath.Join(t.TempDir(), "a.db"))
	l, err := Open(bg, Config{DB: db, Dialect: "sqlite", Flush: time.Millisecond, Queue: 8, Batch: 4, BlockTimeout: 100 * time.Millisecond,
		OnError: func(error) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Make every commit fail by taking the table away.
	_, _ = db.Exec(`ALTER TABLE rtc_audit RENAME TO rtc_audit_gone`)
	accepted, refused := 0, 0
	start := time.Now()
	for i := 0; i < 60; i++ {
		if err := l.Record(Event{Tenant: "t", Action: "x", Outcome: OK}); err == nil {
			accepted++
		} else if err == ErrBackpressure {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("recorders waited %v", time.Since(start))
	}
	if refused == 0 || l.Stats().Refused != int64(refused) {
		t.Fatalf("accepted %d refused %d, stats %+v", accepted, refused, l.Stats())
	}
	if l.Stats().Retries == 0 {
		t.Fatal("the writer did not retry")
	}
	// The store comes back: everything that was accepted is stored, none twice.
	mu.Lock()
	failing = false
	mu.Unlock()
	_, _ = db.Exec(`ALTER TABLE rtc_audit_gone RENAME TO rtc_audit`)
	deadline := time.Now().Add(15 * time.Second)
	for l.Stats().Written < int64(accepted) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	flush(t, l)
	v, _ := l.Verify(bg, "t", 0, 0)
	if !v.OK || int(v.Checked) != accepted {
		t.Fatalf("accepted %d, stored and verified %+v", accepted, v)
	}
	_ = failing
}

func TestTheFileGetsEveryCommittedEntry(t *testing.T) {
	dir := t.TempDir()
	l, _ := newLog(t, func(c *Config) { c.File = filepath.Join(dir, "audit.jsonl") })
	for i := 0; i < 7; i++ {
		rec(t, l, Event{Tenant: "t", Actor: "ada", Action: "call.start", Outcome: OK})
	}
	flush(t, l)
	_ = l.Close()
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 7 || !strings.Contains(lines[6], `"seq":7`) || !strings.Contains(lines[0], `"hash":"`) {
		t.Fatalf("%d lines: %.200s", len(lines), b)
	}
	if st, _ := os.Stat(filepath.Join(dir, "audit.jsonl")); st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the audit file is readable by others: %v", st.Mode())
	}
}

func TestOddMetaCannotBreakTheLog(t *testing.T) {
	l, _ := newLog(t, nil)
	rec(t, l, Event{Tenant: "t", Action: "x", Outcome: OK, Meta: map[string]any{"bad": make(chan int)}})
	rec(t, l, Event{Tenant: "t", Action: "x", Outcome: OK, Meta: map[string]any{"big": strings.Repeat("a", 5000)}})
	rec(t, l, Event{Tenant: "t", Action: "x\x00y'; DROP TABLE rtc_audit;--", Actor: "a\nb", Outcome: OK})
	flush(t, l)
	got, _ := l.Query(bg, "t", Filter{})
	if len(got) != 3 || got[0].Meta["_error"] == nil || got[1].Meta["_truncated"] != true {
		t.Fatalf("%+v", got)
	}
	if v, _ := l.Verify(bg, "t", 0, 0); !v.OK {
		t.Fatalf("%+v", v)
	}
}

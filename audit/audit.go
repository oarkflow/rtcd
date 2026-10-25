// Package audit is the service's audit log: an append-only record of who did
// what, to what, and whether it was allowed.
//
// Each tenant has its own numbered sequence, and every entry carries the hash of
// the one before it, so an entry that is altered, removed or inserted after the
// fact breaks the chain and Verify finds it. The chain proves tampering after
// the entries were written; it cannot, by itself, prove that the newest entries
// were not cut off the end, so ship the optional JSONL file (or the head hash
// from Head) somewhere the database's administrator cannot reach.
//
// Recording never touches the database on the caller's goroutine: entries go to
// a bounded queue and one writer commits them in batches. A caller is slowed
// only if the queue is full, and gets ErrBackpressure rather than waiting
// forever.
package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Outcomes.
const (
	OK     = "ok"
	Denied = "denied" // the caller was not allowed
	Failed = "error"  // the operation was allowed but did not succeed
)

// NoTenant is the tenant under which events that cannot be tied to one are
// recorded, such as a request that failed to authenticate.
const NoTenant = "_none"

// ErrBackpressure is returned by Record when the queue stayed full.
var ErrBackpressure = errors.New("audit: the log cannot keep up")

// ErrClosed is returned after Close.
var ErrClosed = errors.New("audit: closed")

// Event is one audit entry.
type Event struct {
	Tenant    string         `json:"tenant"`
	Seq       uint64         `json:"seq"` // set by the log
	Time      time.Time      `json:"time"`
	Actor     string         `json:"actor,omitempty"`   // the user the action was done as
	Service   string         `json:"service,omitempty"` // the API key's name, when a service did it
	Action    string         `json:"action"`
	Target    string         `json:"target,omitempty"` // the call or group acted on
	Outcome   string         `json:"outcome"`
	Code      string         `json:"code,omitempty"` // why it was denied or failed
	IP        string         `json:"ip,omitempty"`
	Transport string         `json:"transport,omitempty"` // ws or http
	Conn      string         `json:"conn,omitempty"`      // the websocket connection
	Meta      map[string]any `json:"meta,omitempty"`      // small facts: sizes, counts, other users. Never message contents.
	Prev      string         `json:"prev"`                // set by the log
	Hash      string         `json:"hash"`                // set by the log
}

const tsLayout = "2006-01-02T15:04:05.000000000Z"

// MaxMeta is the largest JSON the Meta of one event may encode to.
const MaxMeta = 2048

// Config configures a Log.
type Config struct {
	DB      *sql.DB
	Dialect string // sqlite, postgres or mysql
	Rebind  func(string) string
	// File, when set, also receives every committed entry as one JSON line.
	File string
	// Queue is how many entries may be recorded and not yet stored before
	// Record starts to wait. Default 16384.
	Queue int
	// Batch is the most entries one commit takes. Default 512.
	Batch int
	// Flush is how long a partial batch waits for company. Default 50ms.
	Flush time.Duration
	// BlockTimeout is how long Record waits for room in a full queue. Default 2s.
	BlockTimeout time.Duration
	// OnError hears about commit failures (they are retried).
	OnError func(error)
	Now     func() time.Time
}

// Log is an audit log.
type Log struct {
	cfg    Config
	rebind func(string) string
	bufs   [bufShards]buf
	wake   chan struct{}
	flushq chan chan struct{}
	stop   chan struct{}
	done   chan struct{}
	closed atomic.Bool
	file   *os.File
	fw     *bufio.Writer

	state map[string]head // writer goroutine only

	pending                           atomic.Int64 // recorded and not yet stored
	queued, written, retries, refused atomic.Int64
}

// bufShards is how many buffers producers spread over. An entry goes to the
// buffer of its session, so the entries of one connection stay in order and
// requests from different connections never share a lock.
const bufShards = 32

type buf struct {
	mu  sync.Mutex
	evs []Event
	_   [40]byte // keep neighbouring buffers off one cache line
}

type head struct {
	seq  uint64
	hash string
}

// Open prepares the schema and starts the writer.
func Open(ctx context.Context, cfg Config) (*Log, error) {
	if cfg.DB == nil {
		return nil, errors.New("audit: a database is required")
	}
	if cfg.Queue <= 0 {
		cfg.Queue = 16384
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 512
	}
	if cfg.Flush <= 0 {
		cfg.Flush = 50 * time.Millisecond
	}
	if cfg.BlockTimeout <= 0 {
		cfg.BlockTimeout = 2 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	l := &Log{cfg: cfg, rebind: cfg.Rebind, wake: make(chan struct{}, 1), flushq: make(chan chan struct{}), stop: make(chan struct{}), done: make(chan struct{}), state: map[string]head{}}
	if l.rebind == nil {
		l.rebind = func(q string) string { return q }
	}
	key := "VARCHAR(191)"
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS rtc_audit (tenant ` + key + ` NOT NULL, seq BIGINT NOT NULL, ts VARCHAR(40) NOT NULL,
			actor ` + key + ` NOT NULL, service ` + key + ` NOT NULL, action ` + key + ` NOT NULL, target ` + key + ` NOT NULL,
			outcome VARCHAR(16) NOT NULL, code ` + key + ` NOT NULL, ip VARCHAR(64) NOT NULL, transport VARCHAR(8) NOT NULL,
			conn ` + key + ` NOT NULL, meta TEXT NOT NULL, prev VARCHAR(64) NOT NULL, hash VARCHAR(64) NOT NULL,
			PRIMARY KEY (tenant, seq))`,
		`CREATE INDEX IF NOT EXISTS rtc_audit_actor ON rtc_audit (tenant, actor, seq)`,
		`CREATE INDEX IF NOT EXISTS rtc_audit_target ON rtc_audit (tenant, target, seq)`,
		`CREATE INDEX IF NOT EXISTS rtc_audit_action ON rtc_audit (tenant, action, seq)`,
	} {
		if _, err := cfg.DB.ExecContext(ctx, q); err != nil {
			return nil, fmt.Errorf("audit: schema: %w", err)
		}
	}
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		l.file, l.fw = f, bufio.NewWriterSize(f, 64<<10)
	}
	go l.run()
	return l, nil
}

// Record queues an entry. It returns once the entry is queued, not once it is
// stored; call Flush to wait for storage. It takes a lock shared only with the
// same session's other entries, and waits only if the backlog is full.
func (l *Log) Record(e Event) error {
	if l.closed.Load() {
		return ErrClosed
	}
	if e.Time.IsZero() {
		e.Time = l.cfg.Now()
	}
	if e.Tenant == "" {
		e.Tenant = NoTenant
	}
	if l.pending.Load() >= int64(l.cfg.Queue) {
		if err := l.waitForRoom(); err != nil {
			return err
		}
	}
	b := &l.bufs[shardOf(e)]
	b.mu.Lock()
	b.evs = append(b.evs, e)
	b.mu.Unlock()
	l.queued.Add(1)
	if n := l.pending.Add(1); n >= int64(l.cfg.Batch) && n%int64(l.cfg.Batch) == 0 {
		select {
		case l.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func shardOf(e Event) uint32 {
	h := uint32(2166136261)
	for _, s := range [...]string{e.Conn, e.Actor, e.Service, e.Tenant} {
		for i := 0; i < len(s); i++ {
			h ^= uint32(s[i])
			h *= 16777619
		}
	}
	return h % bufShards
}

// waitForRoom is the slow path, taken only when the backlog is full: the store
// cannot keep up. Callers wait a little for it, then are told.
func (l *Log) waitForRoom() error {
	deadline := time.Now().Add(l.cfg.BlockTimeout)
	for l.pending.Load() >= int64(l.cfg.Queue) {
		if l.closed.Load() {
			return ErrClosed
		}
		if time.Now().After(deadline) {
			l.refused.Add(1)
			return ErrBackpressure
		}
		select {
		case l.wake <- struct{}{}:
		default:
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}

// Flush returns when everything recorded before the call has been stored (or
// ctx is done).
func (l *Log) Flush(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case l.flushq <- done:
	case <-ctx.Done():
		return ctx.Err()
	case <-l.stop:
		return ErrClosed
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stores what is queued and stops the writer.
func (l *Log) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(l.stop)
	<-l.done
	if l.file != nil {
		_ = l.fw.Flush()
		_ = l.file.Sync()
		return l.file.Close()
	}
	return nil
}

// Stats are the log's counters.
type Stats struct {
	Queued, Written, Retries, Refused int64
	Waiting                           int
}

// Stats returns the counters. Refused counts entries Record could not queue;
// those are not in the log.
func (l *Log) Stats() Stats {
	return Stats{Queued: l.queued.Load(), Written: l.written.Load(), Retries: l.retries.Load(), Refused: l.refused.Load(), Waiting: int(l.pending.Load())}
}

// ---------------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------------

func (l *Log) run() {
	defer close(l.done)
	timer := time.NewTicker(l.cfg.Flush)
	defer timer.Stop()
	var batch []Event
	// take moves everything buffered into batch.
	take := func() {
		for i := range l.bufs {
			b := &l.bufs[i]
			b.mu.Lock()
			if len(b.evs) > 0 {
				batch = append(batch, b.evs...)
				b.evs = b.evs[:0]
			}
			b.mu.Unlock()
		}
	}
	// commitAll stores what has been taken, in batches of at most cfg.Batch.
	commitAll := func() {
		for len(batch) > 0 {
			n := min(len(batch), l.cfg.Batch)
			l.commit(batch[:n])
			l.pending.Add(-int64(n))
			batch = batch[n:]
		}
		batch = batch[:0:0]
	}
	for {
		select {
		case <-l.wake:
			take()
			commitAll()
		case <-timer.C:
			take()
			commitAll()
		case done := <-l.flushq:
			take()
			commitAll()
			close(done)
		case <-l.stop:
			take()
			commitAll()
			return
		}
	}
}

// commit chains and stores a batch, retrying until it succeeds: an entry that
// was accepted is not given up on.
func (l *Log) commit(batch []Event) {
	delay := 50 * time.Millisecond
	for {
		out, heads, err := l.chain(batch)
		if err == nil {
			err = l.store(out)
		}
		if err == nil {
			for t, h := range heads {
				l.state[t] = h
			}
			l.written.Add(int64(len(out)))
			l.ship(out)
			return
		}
		l.retries.Add(1)
		if l.cfg.OnError != nil {
			l.cfg.OnError(err)
		}
		select {
		case <-time.After(delay):
		case <-l.stop:
			// Shutting down with the store unreachable: give the entries to the
			// file at least, unchained to a stored head, rather than lose them.
			if out, _, cerr := l.chain(batch); cerr == nil {
				l.ship(out)
			}
			return
		}
		if delay < 5*time.Second {
			delay *= 2
		}
	}
}

// chain gives each event its sequence number and hashes, without recording them
// as committed yet.
func (l *Log) chain(batch []Event) ([]Event, map[string]head, error) {
	heads := map[string]head{}
	out := make([]Event, len(batch))
	for i, e := range batch {
		h, ok := heads[e.Tenant]
		if !ok {
			if h, ok = l.state[e.Tenant]; !ok {
				var err error
				if h, err = l.load(e.Tenant); err != nil {
					return nil, nil, err
				}
			}
		}
		e.Seq, e.Prev = h.seq+1, h.hash
		if e.Prev == "" {
			e.Prev = strings.Repeat("0", 64)
		}
		e.Time = e.Time.UTC()
		e.Hash = hashOf(e, encodeMeta(e.Meta))
		heads[e.Tenant] = head{e.Seq, e.Hash}
		out[i] = e
	}
	return out, heads, nil
}

func (l *Log) load(tenant string) (head, error) {
	var h head
	err := l.cfg.DB.QueryRow(l.rebind(`SELECT seq, hash FROM rtc_audit WHERE tenant = $1 ORDER BY seq DESC LIMIT 1`), tenant).Scan(&h.seq, &h.hash)
	if errors.Is(err, sql.ErrNoRows) {
		return head{}, nil
	}
	return h, err
}

func (l *Log) store(batch []Event) error {
	tx, err := l.cfg.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(l.rebind(`INSERT INTO rtc_audit (tenant, seq, ts, actor, service, action, target, outcome, code, ip, transport, conn, meta, prev, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`))
	if err != nil {
		return err
	}
	defer st.Close()
	for _, e := range batch {
		if _, err := st.Exec(e.Tenant, e.Seq, e.Time.Format(tsLayout), e.Actor, e.Service, e.Action, e.Target, e.Outcome, e.Code, e.IP, e.Transport, e.Conn, encodeMeta(e.Meta), e.Prev, e.Hash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (l *Log) ship(batch []Event) {
	if l.file == nil {
		return
	}
	for _, e := range batch {
		b, _ := json.Marshal(e)
		_, _ = l.fw.Write(append(b, '\n'))
	}
	_ = l.fw.Flush()
}

func encodeMeta(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m) // map keys are sorted, so this is canonical
	if err != nil {
		return `{"_error":"meta could not be encoded"}`
	}
	if len(b) > MaxMeta {
		return `{"_truncated":true}`
	}
	return string(b)
}

// hashOf is the hash of an entry: every field, each with its length, so no two
// different entries can be written the same way.
func hashOf(e Event, meta string) string {
	h := sha256.New()
	w := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], e.Seq)
	h.Write(seq[:])
	for _, s := range []string{e.Tenant, e.Time.UTC().Format(tsLayout), e.Actor, e.Service, e.Action, e.Target, e.Outcome, e.Code, e.IP, e.Transport, e.Conn, meta, e.Prev} {
		w(s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// Filter selects entries. Zero fields match everything.
type Filter struct {
	Actor, Target, Outcome string
	// Action matches exactly, or as a prefix when it ends in ".": "call." is
	// every call action.
	Action   string
	From, To time.Time
	AfterSeq uint64
	Limit    int // default 100, at most 1000
	Newest   bool
}

// Query returns a tenant's entries, oldest first (or newest first).
func (l *Log) Query(ctx context.Context, tenant string, f Filter) ([]Event, error) {
	if tenant == "" {
		return nil, errors.New("audit: a tenant is required")
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 1000 {
		f.Limit = 1000
	}
	q := `SELECT tenant, seq, ts, actor, service, action, target, outcome, code, ip, transport, conn, meta, prev, hash FROM rtc_audit WHERE tenant = $1`
	args := []any{tenant}
	add := func(cond string, v any) {
		args = append(args, v)
		q += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.Actor != "" {
		add("actor = $%d", f.Actor)
	}
	if f.Target != "" {
		add("target = $%d", f.Target)
	}
	if f.Outcome != "" {
		add("outcome = $%d", f.Outcome)
	}
	if f.Action != "" {
		if strings.HasSuffix(f.Action, ".") {
			add("action >= $%d", f.Action)
			add("action < $%d", f.Action+"\U0010ffff")
		} else {
			add("action = $%d", f.Action)
		}
	}
	if !f.From.IsZero() {
		add("ts >= $%d", f.From.UTC().Format(tsLayout))
	}
	if !f.To.IsZero() {
		add("ts < $%d", f.To.UTC().Format(tsLayout))
	}
	if f.AfterSeq > 0 {
		if f.Newest {
			add("seq < $%d", f.AfterSeq)
		} else {
			add("seq > $%d", f.AfterSeq)
		}
	}
	if f.Newest {
		q += " ORDER BY seq DESC"
	} else {
		q += " ORDER BY seq ASC"
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(" LIMIT $%d", len(args))
	rows, err := l.cfg.DB.QueryContext(ctx, l.rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, _, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scan(rows *sql.Rows) (Event, string, error) {
	var e Event
	var ts, meta string
	if err := rows.Scan(&e.Tenant, &e.Seq, &ts, &e.Actor, &e.Service, &e.Action, &e.Target, &e.Outcome, &e.Code, &e.IP, &e.Transport, &e.Conn, &meta, &e.Prev, &e.Hash); err != nil {
		return e, "", err
	}
	t, err := time.Parse(tsLayout, ts)
	if err != nil {
		return e, "", err
	}
	e.Time = t
	if meta != "" && meta != "{}" {
		_ = json.Unmarshal([]byte(meta), &e.Meta)
	}
	return e, meta, nil
}

// Head is the newest entry's sequence number and hash for a tenant. Keep it
// somewhere else: entries cut off the end cannot be noticed from inside.
func (l *Log) Head(ctx context.Context, tenant string) (uint64, string, error) {
	var seq uint64
	var hash string
	err := l.cfg.DB.QueryRowContext(ctx, l.rebind(`SELECT seq, hash FROM rtc_audit WHERE tenant = $1 ORDER BY seq DESC LIMIT 1`), tenant).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	return seq, hash, err
}

// Verification is the result of Verify.
type Verification struct {
	Checked uint64 `json:"checked"`
	LastSeq uint64 `json:"last_seq"`
	OK      bool   `json:"ok"`
	// BadSeq and Reason say where and how the chain is broken.
	BadSeq uint64 `json:"bad_seq,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Verify walks a tenant's chain from entry afterSeq+1 and checks that every
// entry is numbered after the one before it, links to its hash, and hashes to
// what is stored. It checks at most limit entries (default 100000).
func (l *Log) Verify(ctx context.Context, tenant string, afterSeq uint64, limit int) (Verification, error) {
	if limit <= 0 {
		limit = 100000
	}
	v := Verification{OK: true, LastSeq: afterSeq}
	prevHash := strings.Repeat("0", 64)
	if afterSeq > 0 {
		var h string
		err := l.cfg.DB.QueryRowContext(ctx, l.rebind(`SELECT hash FROM rtc_audit WHERE tenant = $1 AND seq = $2`), tenant, afterSeq).Scan(&h)
		if errors.Is(err, sql.ErrNoRows) {
			return Verification{OK: false, BadSeq: afterSeq, Reason: "the entry to start after does not exist"}, nil
		}
		if err != nil {
			return v, err
		}
		prevHash = h
	}
	rows, err := l.cfg.DB.QueryContext(ctx, l.rebind(`SELECT tenant, seq, ts, actor, service, action, target, outcome, code, ip, transport, conn, meta, prev, hash FROM rtc_audit WHERE tenant = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3`), tenant, afterSeq, limit)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	want := afterSeq + 1
	for rows.Next() {
		e, meta, err := scan(rows)
		if err != nil {
			return v, err
		}
		bad := func(reason string) (Verification, error) {
			v.OK, v.BadSeq, v.Reason = false, e.Seq, reason
			return v, nil
		}
		switch {
		case e.Seq != want:
			return bad(fmt.Sprintf("entries %d to %d are missing", want, e.Seq-1))
		case e.Prev != prevHash:
			return bad("the entry does not link to the one before it")
		case hashOf(e, meta) != e.Hash:
			return bad("the entry was changed after it was written")
		}
		prevHash, want = e.Hash, want+1
		v.Checked, v.LastSeq = v.Checked+1, e.Seq
	}
	return v, rows.Err()
}

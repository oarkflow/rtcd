// Package chat stores messages and the metadata of attachments.
//
// The service never reads either. A message body is an opaque string the
// sender's client encrypted (the server stores and forwards it); an attachment
// is a ciphertext blob, and the key to it travels inside an encrypted message.
// What the server can enforce is who may send and fetch, sizes, rates and
// retention.
package chat

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/oarkflow/rtcd/dbx"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid   = errors.New("chat: invalid request")
	ErrNotFound  = errors.New("chat: not found")
	ErrForbidden = errors.New("chat: forbidden")
	ErrLimit     = errors.New("chat: limit reached")
	ErrState     = errors.New("chat: wrong state")
	ErrWindow    = errors.New("chat: past the time a message can be deleted")
)

// Message is one stored message.
type Message struct {
	Conv    string    `json:"conv"`
	Seq     int64     `json:"seq"`
	ID      string    `json:"id"` // the sender's id for it, unique per sender and conversation
	Sender  string    `json:"sender"`
	Sent    time.Time `json:"sent_at"`
	Body    string    `json:"body,omitempty"`
	Deleted bool      `json:"deleted,omitempty"`
	// Epoch is the conversation key generation the sender sealed the body under
	// (0: the conversation does not use epochs). Expires is when the message
	// disappears, if it was sent with a lifetime.
	Epoch   int64      `json:"epoch,omitempty"`
	Expires *time.Time `json:"expires_at,omitempty"`
}

// SendIn is a message to store.
type SendIn struct {
	Tenant, Conv, Sender, ID, Body string
	Epoch                          int64
	// TTL is how long the message lives (0: until retention removes it).
	TTL time.Duration
}

// Options configure a Store.
type Options struct {
	Dialect string
	Rebind  func(string) string
	// MaxBody is the largest message body in bytes. Default 32 KiB.
	MaxBody int
	Now     func() time.Time
}

// Store keeps messages in SQL.
type Store struct {
	db       *sql.DB
	o        Options
	rebind   func(string) string
	locks    [64]sync.Mutex
	cmu      sync.Mutex
	qmu      sync.Mutex
	queues   map[string]*convQueue
	counters map[string]int64 // conversation -> newest number this node wrote
	states   stateCache
}

// Open prepares the schema.
func Open(ctx context.Context, db *sql.DB, o Options) (*Store, error) {
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 32 << 10
	}
	s := &Store{db: db, o: o, rebind: o.Rebind, counters: map[string]int64{}, queues: map[string]*convQueue{}}
	if s.rebind == nil {
		s.rebind = func(q string) string { return q }
	}
	key := "VARCHAR(191)"
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS rtc_messages (tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL, seq BIGINT NOT NULL,
			id ` + key + ` NOT NULL, sender ` + key + ` NOT NULL, sent_at BIGINT NOT NULL, body TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
			epoch BIGINT NOT NULL DEFAULT 0, expires_at BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant, conv, seq))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS rtc_messages_idem ON rtc_messages (tenant, conv, sender, id)`,
		`CREATE INDEX IF NOT EXISTS rtc_messages_age ON rtc_messages (sent_at)`,
		`CREATE TABLE IF NOT EXISTS rtc_msg_cursor (tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL, user_id ` + key + ` NOT NULL,
			seq BIGINT NOT NULL, PRIMARY KEY (tenant, conv, user_id))`,
		`CREATE TABLE IF NOT EXISTS rtc_files (id ` + key + ` PRIMARY KEY, tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL,
			owner ` + key + ` NOT NULL, size BIGINT NOT NULL, chunk BIGINT NOT NULL, sha256 ` + key + ` NOT NULL, state VARCHAR(16) NOT NULL,
			created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS rtc_files_conv ON rtc_files (tenant, conv)`,
		`CREATE INDEX IF NOT EXISTS rtc_files_exp ON rtc_files (expires_at)`,
	} {
		if err := dbx.DDL(ctx, db, o.Dialect, q); err != nil {
			return nil, fmt.Errorf("chat: schema: %w", err)
		}
	}
	// Tables made by an earlier version lack the newer columns.
	for _, c := range [][3]string{{"rtc_messages", "epoch", "BIGINT NOT NULL DEFAULT 0"}, {"rtc_messages", "expires_at", "BIGINT NOT NULL DEFAULT 0"}} {
		if err := dbx.AddColumn(ctx, db, c[0], c[1], c[2]); err != nil {
			return nil, fmt.Errorf("chat: schema: %w", err)
		}
	}
	if err := s.openKeys(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) lock(tenant, conv string) *sync.Mutex {
	h := uint32(2166136261)
	for _, c := range []byte(tenant + "\x00" + conv) {
		h = (h ^ uint32(c)) * 16777619
	}
	return &s.locks[h%uint32(len(s.locks))]
}

// sendOne stores one message and gives it the next number in its conversation. A
// retry with the same id from the same sender returns the message already stored
// (dup is true), so a client can resend after a dropped connection safely.
//
// In the usual case this is one INSERT and nothing else: the next number comes
// from a counter held in memory under the conversation's lock. If another node
// has written to the conversation, the INSERT collides on the primary key, the
// counter is reloaded, and it is tried again.
func (s *Store) sendOne(ctx context.Context, in SendIn, at, exp int64) (m Message, dup bool, err error) {
	tenant, conv := in.Tenant, in.Conv
	key := tenant + "\x00" + conv
	mu := s.lock(tenant, conv)
	mu.Lock()
	defer mu.Unlock()
	for try := 0; try < 6; try++ {
		s.cmu.Lock()
		seq, ok := s.counters[key]
		s.cmu.Unlock()
		if !ok {
			var max sql.NullInt64
			if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT MAX(seq) FROM rtc_messages WHERE tenant=$1 AND conv=$2`), tenant, conv).Scan(&max); err != nil {
				return Message{}, false, err
			}
			seq = max.Int64
		}
		seq++
		_, err = s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_messages (tenant, conv, seq, id, sender, sent_at, body, epoch, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`),
			tenant, conv, seq, in.ID, in.Sender, at, in.Body, in.Epoch, exp)
		if err == nil {
			s.setCounter(key, seq)
			return stored(conv, seq, in, at, exp), false, nil
		}
		if !dbx.IsDuplicate(err) && !dbx.IsRetryable(err) {
			return Message{}, false, err
		}
		// Either this id was sent before (return it), or the number was taken by
		// another node (forget the counter and try the next one).
		var oseq, oat, oep int64
		switch e := s.db.QueryRowContext(ctx, s.rebind(`SELECT seq, sent_at, epoch FROM rtc_messages WHERE tenant=$1 AND conv=$2 AND sender=$3 AND id=$4`), tenant, conv, in.Sender, in.ID).Scan(&oseq, &oat, &oep); {
		case e == nil:
			return Message{Conv: conv, Seq: oseq, ID: in.ID, Sender: in.Sender, Sent: time.UnixMilli(oat).UTC(), Epoch: oep}, true, nil
		case !errors.Is(e, sql.ErrNoRows):
			return Message{}, false, e
		}
		s.dropCounter(key)
	}
	return Message{}, false, err
}

func stored(conv string, seq int64, in SendIn, at, exp int64) Message {
	m := Message{Conv: conv, Seq: seq, ID: in.ID, Sender: in.Sender, Sent: time.UnixMilli(at).UTC(), Body: in.Body, Epoch: in.Epoch}
	if exp > 0 {
		t := time.UnixMilli(exp).UTC()
		m.Expires = &t
	}
	return m
}

// MaxTTL is the longest a message may be asked to live.
const MaxTTL = 366 * 24 * time.Hour

func (s *Store) valid(in SendIn) bool {
	return in.Tenant != "" && in.Conv != "" && in.Sender != "" && in.ID != "" && len(in.ID) <= 64 && in.Body != "" && len(in.Body) <= s.o.MaxBody &&
		in.Epoch >= 0 && in.TTL >= 0 && in.TTL <= MaxTTL
}

func (s *Store) setCounter(key string, seq int64) {
	s.cmu.Lock()
	if len(s.counters) > 50000 {
		s.counters = map[string]int64{}
	}
	s.counters[key] = seq
	s.cmu.Unlock()
}

func (s *Store) dropCounter(key string) {
	s.cmu.Lock()
	delete(s.counters, key)
	s.cmu.Unlock()
}

// History returns up to limit messages: those after `after` (oldest first), or,
// when before is set, those before it (newest first). Messages past their
// lifetime are not returned even before they are removed from disk.
func (s *Store) History(ctx context.Context, tenant, conv string, after, before int64, limit int) ([]Message, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	now := s.o.Now().UnixMilli()
	q := `SELECT seq, id, sender, sent_at, body, deleted, epoch, expires_at FROM rtc_messages WHERE tenant=$1 AND conv=$2 AND seq>$3 AND (expires_at=0 OR expires_at>$4) `
	args := []any{tenant, conv, after, now}
	order := " ORDER BY seq ASC"
	if before > 0 {
		q += "AND seq<$5 "
		args = append(args, before)
		order = " ORDER BY seq DESC"
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(q+order+fmt.Sprintf(" LIMIT %d", limit)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		var at, exp int64
		var del int
		if err := rows.Scan(&m.Seq, &m.ID, &m.Sender, &at, &m.Body, &del, &m.Epoch, &exp); err != nil {
			return nil, err
		}
		m.Conv, m.Sent, m.Deleted = conv, time.UnixMilli(at).UTC(), del != 0
		if exp > 0 {
			t := time.UnixMilli(exp).UTC()
			m.Expires = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Delete blanks a message (the number stays, so history has no gap). byAdmin
// lets someone other than the sender do it. A sender may delete only within
// window of sending it (0: any time); an admin is not held to it.
func (s *Store) Delete(ctx context.Context, tenant, conv string, seq int64, by string, byAdmin bool, window time.Duration) error {
	var sender string
	var sent int64
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT sender, sent_at FROM rtc_messages WHERE tenant=$1 AND conv=$2 AND seq=$3`), tenant, conv, seq).Scan(&sender, &sent)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if sender != by && !byAdmin {
		return ErrForbidden
	}
	if !byAdmin && window > 0 && s.o.Now().Sub(time.UnixMilli(sent)) > window {
		return fmt.Errorf("%w: a message can be deleted for everyone only %s after it was sent", ErrWindow, window)
	}
	_, err = s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_messages SET body='-', deleted=1 WHERE tenant=$1 AND conv=$2 AND seq=$3`), tenant, conv, seq)
	return err
}

// MarkRead moves a user's read position forward (never back).
func (s *Store) MarkRead(ctx context.Context, tenant, conv, user string, seq int64) (int64, error) {
	var cur int64
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT seq FROM rtc_msg_cursor WHERE tenant=$1 AND conv=$2 AND user_id=$3`), tenant, conv, user).Scan(&cur)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_msg_cursor (tenant, conv, user_id, seq) VALUES ($1,$2,$3,$4)`), tenant, conv, user, seq)
		return seq, err
	case err != nil:
		return 0, err
	case seq <= cur:
		return cur, nil
	}
	_, err = s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_msg_cursor SET seq=$1 WHERE tenant=$2 AND conv=$3 AND user_id=$4`), seq, tenant, conv, user)
	return seq, err
}

// Cursor is one member's read position.
type Cursor struct {
	User string `json:"user"`
	Seq  int64  `json:"seq"`
}

// Cursors returns every read position recorded in a conversation.
func (s *Store) Cursors(ctx context.Context, tenant, conv string) ([]Cursor, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT user_id, seq FROM rtc_msg_cursor WHERE tenant=$1 AND conv=$2`), tenant, conv)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Cursor{}
	for rows.Next() {
		var c Cursor
		if err := rows.Scan(&c.User, &c.Seq); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Summary is where a conversation stands for one reader.
type Summary struct {
	Conv    string     `json:"conv"`
	LastSeq int64      `json:"last_seq"`
	LastAt  *time.Time `json:"last_at,omitempty"`
	ReadSeq int64      `json:"read_seq"`
	// Unread counts messages after ReadSeq that others sent, capped at 100.
	Unread int `json:"unread"`
}

// Summaries answers, for each conversation, the newest message and the reader's
// position, so a conversation list can show badges without fetching history.
func (s *Store) Summaries(ctx context.Context, tenant, user string, convs []string) ([]Summary, error) {
	out := make([]Summary, 0, len(convs))
	now := s.o.Now().UnixMilli()
	for _, c := range convs {
		sm := Summary{Conv: c}
		var at sql.NullInt64
		var max sql.NullInt64
		if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT MAX(seq), MAX(sent_at) FROM rtc_messages WHERE tenant=$1 AND conv=$2 AND (expires_at=0 OR expires_at>$3)`), tenant, c, now).Scan(&max, &at); err != nil {
			return nil, err
		}
		sm.LastSeq = max.Int64
		if at.Valid {
			t := time.UnixMilli(at.Int64).UTC()
			sm.LastAt = &t
		}
		err := s.db.QueryRowContext(ctx, s.rebind(`SELECT seq FROM rtc_msg_cursor WHERE tenant=$1 AND conv=$2 AND user_id=$3`), tenant, c, user).Scan(&sm.ReadSeq)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if sm.LastSeq > sm.ReadSeq {
			if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM (SELECT seq FROM rtc_messages WHERE tenant=$1 AND conv=$2 AND seq>$3 AND sender<>$4 AND deleted=0 AND (expires_at=0 OR expires_at>$5) LIMIT 100) x`), tenant, c, sm.ReadSeq, user, now).Scan(&sm.Unread); err != nil {
				return nil, err
			}
		}
		out = append(out, sm)
	}
	return out, nil
}

// Prune deletes messages older than keep (0: no age limit), messages past their
// own lifetime, and messages older than a conversation's own retention, and
// returns how many.
func (s *Store) Prune(ctx context.Context, keep time.Duration) (int64, error) {
	now := s.o.Now()
	var total int64
	run := func(q string, args ...any) error {
		r, err := s.db.ExecContext(ctx, s.rebind(q), args...)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		total += n
		return nil
	}
	if keep > 0 {
		if err := run(`DELETE FROM rtc_messages WHERE sent_at<$1`, now.Add(-keep).UnixMilli()); err != nil {
			return total, err
		}
	}
	if err := run(`DELETE FROM rtc_messages WHERE expires_at>0 AND expires_at<$1`, now.UnixMilli()); err != nil {
		return total, err
	}
	// A conversation's own retention. The subquery reads another table, which
	// MySQL allows in a DELETE.
	err := run(`DELETE FROM rtc_messages WHERE EXISTS (SELECT 1 FROM rtc_conv c WHERE c.tenant = rtc_messages.tenant AND c.conv = rtc_messages.conv AND c.retention_s > 0 AND rtc_messages.sent_at < $1 - c.retention_s * 1000)`, now.UnixMilli())
	return total, err
}

// PurgeConv removes everything kept for a conversation (messages, read
// positions, wrapped keys, its policy) and returns the ids of its files, for
// the caller to remove from disk.
func (s *Store) PurgeConv(ctx context.Context, tenant, conv string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT id FROM rtc_files WHERE tenant=$1 AND conv=$2`), tenant, conv)
	if err != nil {
		return nil, err
	}
	var files []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		files = append(files, id)
	}
	rows.Close()
	for _, q := range []string{
		`DELETE FROM rtc_messages WHERE tenant=$1 AND conv=$2`,
		`DELETE FROM rtc_msg_cursor WHERE tenant=$1 AND conv=$2`,
		`DELETE FROM rtc_epoch_keys WHERE tenant=$1 AND conv=$2`,
		`DELETE FROM rtc_conv WHERE tenant=$1 AND conv=$2`,
	} {
		if _, err := s.db.ExecContext(ctx, s.rebind(q), tenant, conv); err != nil {
			return files, err
		}
	}
	s.dropState(tenant, conv)
	s.dropCounter(tenant + "\x00" + conv)
	return files, nil
}

// ---------------------------------------------------------------------------
// Attachments.
// ---------------------------------------------------------------------------

// File states.
const (
	Uploading = "uploading"
	Ready     = "ready"
)

// File describes one attachment.
type File struct {
	ID      string    `json:"id"`
	Conv    string    `json:"conv"`
	Owner   string    `json:"owner"`
	Size    int64     `json:"size"`
	Chunk   int64     `json:"chunk"`
	SHA256  string    `json:"sha256"` // of the stored (encrypted) bytes
	State   string    `json:"state"`
	Created time.Time `json:"created_at"`
	Expires time.Time `json:"expires_at"`
}

// Chunks is how many parts the file has.
func (f File) Chunks() int64 { return (f.Size + f.Chunk - 1) / f.Chunk }

func newFileID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "fil_" + hex.EncodeToString(b)
}

// ValidSHA reports whether s is a lowercase hex SHA-256.
func ValidSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// Quota bounds what a user and a tenant may hold.
type Quota struct {
	MaxFile        int64 // bytes in one file
	PendingPerUser int   // uploads under way
	TenantBytes    int64 // bytes the tenant holds in total (0: no limit)
}

// NewFile registers an upload.
func (s *Store) NewFile(ctx context.Context, tenant, conv, owner string, size, chunk int64, sha string, ttl time.Duration, q Quota) (File, error) {
	if size <= 0 || chunk <= 0 || !ValidSHA(sha) || size > q.MaxFile {
		return File{}, ErrInvalid
	}
	var pending int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_files WHERE tenant=$1 AND owner=$2 AND state=$3`), tenant, owner, Uploading).Scan(&pending); err != nil {
		return File{}, err
	}
	if q.PendingPerUser > 0 && pending >= q.PendingPerUser {
		return File{}, fmt.Errorf("%w: too many uploads under way", ErrLimit)
	}
	if q.TenantBytes > 0 {
		var used sql.NullInt64
		if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT SUM(size) FROM rtc_files WHERE tenant=$1`), tenant).Scan(&used); err != nil {
			return File{}, err
		}
		if used.Int64+size > q.TenantBytes {
			return File{}, fmt.Errorf("%w: the tenant's storage is full", ErrLimit)
		}
	}
	now := s.o.Now().UTC()
	f := File{ID: newFileID(), Conv: conv, Owner: owner, Size: size, Chunk: chunk, SHA256: sha, State: Uploading, Created: now, Expires: now.Add(ttl)}
	_, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_files (id, tenant, conv, owner, size, chunk, sha256, state, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`),
		f.ID, tenant, conv, owner, size, chunk, sha, Uploading, now.UnixMilli(), f.Expires.UnixMilli())
	return f, err
}

// File returns an attachment of the tenant.
func (s *Store) File(ctx context.Context, tenant, id string) (File, error) {
	var f File
	var c, e int64
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT id, conv, owner, size, chunk, sha256, state, created_at, expires_at FROM rtc_files WHERE tenant=$1 AND id=$2`), tenant, id).
		Scan(&f.ID, &f.Conv, &f.Owner, &f.Size, &f.Chunk, &f.SHA256, &f.State, &c, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	f.Created, f.Expires = time.UnixMilli(c).UTC(), time.UnixMilli(e).UTC()
	return f, err
}

// SetReady marks an upload complete, and extends its life to keep.
func (s *Store) SetReady(ctx context.Context, tenant, id string, keep time.Duration) error {
	r, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_files SET state=$1, expires_at=$2 WHERE tenant=$3 AND id=$4 AND state=$5`),
		Ready, s.o.Now().Add(keep).UnixMilli(), tenant, id, Uploading)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrState
	}
	return nil
}

// DeleteFile removes the record.
func (s *Store) DeleteFile(ctx context.Context, tenant, id string) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_files WHERE tenant=$1 AND id=$2`), tenant, id)
	return err
}

// Expired returns files past their time (tenant, id), for the caller to remove from disk.
func (s *Store) Expired(ctx context.Context, limit int) ([][2]string, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT tenant, id FROM rtc_files WHERE expires_at<$1 LIMIT $2`), s.o.Now().UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var p [2]string
		if err := rows.Scan(&p[0], &p[1]); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Group commit.
// ---------------------------------------------------------------------------

// Messages are numbered in order within a conversation, so a conversation's
// writes cannot overlap. What can be shared is the round trip: while one write
// is on its way, the messages that arrive for the same conversation wait, and
// the next write carries all of them in one INSERT. Under load, a hundred
// people talking at once cost a few statements, not a hundred.
const maxBatch = 100

type pending struct {
	in  SendIn
	res chan sendResult
}

type sendResult struct {
	m   Message
	dup bool
	err error
}

type convQueue struct {
	q       []*pending
	running bool
}

// Send stores a message and gives it the next number in its conversation. A
// retry with the same id from the same sender returns the message already stored
// (dup is true), so a client can resend after a dropped connection safely.
func (s *Store) Send(ctx context.Context, in SendIn) (Message, bool, error) {
	if !s.valid(in) {
		return Message{}, false, ErrInvalid
	}
	key := in.Tenant + "\x00" + in.Conv
	p := &pending{in: in, res: make(chan sendResult, 1)}
	s.qmu.Lock()
	cq := s.queues[key]
	if cq == nil {
		cq = &convQueue{}
		s.queues[key] = cq
	}
	cq.q = append(cq.q, p)
	start := !cq.running
	cq.running = true
	s.qmu.Unlock()
	if start {
		go s.drain(in.Tenant, in.Conv, key, cq)
	}
	select {
	case r := <-p.res:
		return r.m, r.dup, r.err
	case <-ctx.Done():
		return Message{}, false, ctx.Err() // the write may still happen; a retry with the same id finds it
	}
}

func (s *Store) drain(tenant, conv, key string, cq *convQueue) {
	for {
		s.qmu.Lock()
		batch := cq.q
		if len(batch) > maxBatch {
			batch = batch[:maxBatch]
		}
		cq.q = cq.q[len(batch):]
		if len(batch) == 0 {
			cq.running = false
			delete(s.queues, key)
			s.qmu.Unlock()
			return
		}
		s.qmu.Unlock()
		s.commit(tenant, conv, key, batch)
	}
}

func (s *Store) commit(tenant, conv, key string, batch []*pending) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	at := s.o.Now().UTC().UnixMilli()
	expiry := func(p *pending) int64 {
		if p.in.TTL > 0 {
			return at + p.in.TTL.Milliseconds()
		}
		return 0
	}
	one := func(p *pending) {
		m, dup, err := s.sendOne(ctx, p.in, at, expiry(p))
		p.res <- sendResult{m, dup, err}
	}
	if len(batch) == 1 {
		one(batch[0])
		return
	}
	// The same sender and id twice in one batch is a retry: the second waits for the first.
	seen := map[string]bool{}
	var fresh, later []*pending
	for _, p := range batch {
		k := p.in.Sender + "\x00" + p.in.ID
		if seen[k] {
			later = append(later, p)
			continue
		}
		seen[k] = true
		fresh = append(fresh, p)
	}
	mu := s.lock(tenant, conv)
	mu.Lock()
	s.cmu.Lock()
	seq, ok := s.counters[key]
	s.cmu.Unlock()
	if !ok {
		var max sql.NullInt64
		if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT MAX(seq) FROM rtc_messages WHERE tenant=$1 AND conv=$2`), tenant, conv).Scan(&max); err != nil {
			mu.Unlock()
			for _, p := range batch {
				p.res <- sendResult{err: err}
			}
			return
		}
		seq = max.Int64
	}
	var sb strings.Builder
	sb.WriteString(`INSERT INTO rtc_messages (tenant, conv, seq, id, sender, sent_at, body, epoch, expires_at) VALUES `)
	args := make([]any, 0, len(fresh)*9)
	for i, p := range fresh {
		if i > 0 {
			sb.WriteByte(',')
		}
		b := len(args)
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8, b+9)
		args = append(args, tenant, conv, seq+int64(i)+1, p.in.ID, p.in.Sender, at, p.in.Body, p.in.Epoch, expiry(p))
	}
	_, err := s.db.ExecContext(ctx, s.rebind(sb.String()), args...)
	if err == nil {
		s.setCounter(key, seq+int64(len(fresh)))
	}
	mu.Unlock()
	if err != nil {
		// A repeated id, or a number another node took: the one-at-a-time path sorts out which.
		s.dropCounter(key)
		for _, p := range fresh {
			one(p)
		}
	} else {
		for i, p := range fresh {
			p.res <- sendResult{m: stored(conv, seq+int64(i)+1, p.in, at, expiry(p))}
		}
	}
	for _, p := range later { // retries within the batch
		one(p)
	}
}

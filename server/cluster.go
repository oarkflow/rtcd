package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/dbx"
)

// Several nodes sharing one database.
//
// Three things must be seen by every node, and the database is what they share:
//
//   - revocations, so a banned user is refused by every node and a restart does
//     not forget the ban;
//   - WebSocket tickets, so a ticket issued by one node opens a connection on
//     another (a load balancer need not be sticky for that);
//   - events for people, so a message or call event reaches a user whose socket
//     is on another node. Events are written to an outbox that other nodes poll.
//
// Media is not shared: an SFU room lives on one node, so its signaling
// (sfu.* events) is never replicated, and the load balancer must send every
// request for a given call to the node that holds its room (hash the call id).
// Files need a directory every node can reach (a shared volume).
const (
	pollEvery   = 200 * time.Millisecond
	outboxKeep  = time.Minute
	revokeEvery = 2 * time.Second
	gapWait     = 3 * time.Second // how long to look for an outbox row that committed late
	maxGaps     = 2000
	flushWait   = 20 * time.Millisecond // how long the publisher gathers events into one write
	flushMax    = 20000                 // events in one write
	rowsPerStmt = 100
)

// The outbox has a single writer and a single reader on each node, so a node
// never has more than one query of each kind in flight, however many events
// per second it relays: events gathered within a few milliseconds go in one
// multi-row INSERT, and consecutive events with the same payload for different
// people (one message to a group) share a row.
type cluster struct {
	s     *Server
	last  int64 // newest outbox id this node has read
	gaps  map[int64]time.Time
	lastR int64 // newest revocation (unix ns) this node has loaded
	q     chan outEvent
}

type outEvent struct {
	tenant, user, event, from string
	data                      []byte
}

func (s *Server) openCluster(ctx context.Context) error {
	key := "VARCHAR(191)"
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS rtc_revocations (tenant ` + key + ` NOT NULL, user_id ` + key + ` NOT NULL, at BIGINT NOT NULL, PRIMARY KEY (tenant, user_id))`,
		`CREATE INDEX IF NOT EXISTS rtc_revocations_at ON rtc_revocations (at)`,
		`CREATE TABLE IF NOT EXISTS rtc_tickets (id ` + key + ` PRIMARY KEY, who TEXT NOT NULL, expires_at BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS rtc_outbox (id ` + dbx.Serial(s.cfg.Dialect) + `, node ` + key + ` NOT NULL, tenant ` + key + ` NOT NULL,
			users TEXT NOT NULL, event ` + key + ` NOT NULL, sender ` + key + ` NOT NULL, data MEDIUMTEXT_ NOT NULL, at BIGINT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS rtc_outbox_at ON rtc_outbox (at)`,
	} {
		if s.cfg.Dialect == "mysql" {
			q = strings.Replace(q, "MEDIUMTEXT_", "MEDIUMTEXT", 1)
		} else {
			q = strings.Replace(q, "MEDIUMTEXT_", "TEXT", 1)
		}
		if err := dbx.DDL(ctx, s.cfg.DB, s.cfg.Dialect, q); err != nil {
			return fmt.Errorf("rtcd: cluster schema: %w", err)
		}
	}
	s.cl = &cluster{s: s, gaps: map[int64]time.Time{}, q: make(chan outEvent, 32768)}
	// Load what earlier runs and other nodes revoked, so a restart forgets nothing.
	if err := s.cl.loadRevocations(ctx, false); err != nil {
		return err
	}
	if s.cfg.NodeID != "" {
		var max sql.NullInt64
		if err := s.cfg.DB.QueryRowContext(ctx, `SELECT MAX(id) FROM rtc_outbox`).Scan(&max); err != nil {
			return err
		}
		s.cl.last = max.Int64
	}
	return nil
}

func (s *Server) rb(q string) string {
	if s.cfg.Rebind != nil {
		return s.cfg.Rebind(q)
	}
	return q
}

// loadRevocations reads revocations newer than the last seen. closeConns closes
// the live connections of users revoked by another node.
func (c *cluster) loadRevocations(ctx context.Context, closeConns bool) error {
	rows, err := c.s.cfg.DB.QueryContext(ctx, c.s.rb(`SELECT tenant, user_id, at FROM rtc_revocations WHERE at>$1`), c.lastR)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t, u string
		var at int64
		if err := rows.Scan(&t, &u, &at); err != nil {
			return err
		}
		c.s.auth.RevokeAt(t, u, at)
		if at > c.lastR {
			c.lastR = at
		}
		if closeConns {
			c.s.hubs.closeUser(t, u, "revoked")
		}
	}
	return rows.Err()
}

// revoke records a revocation for every node, and for the next start.
func (s *Server) revoke(ctx context.Context, tenant, user string) (int, error) {
	at := s.auth.Revoke(tenant, user)
	res, err := s.cfg.DB.ExecContext(ctx, s.rb(`UPDATE rtc_revocations SET at=$1 WHERE tenant=$2 AND user_id=$3`), at, tenant, user)
	if err == nil {
		if n, _ := res.RowsAffected(); n == 0 {
			_, err = s.cfg.DB.ExecContext(ctx, s.rb(`INSERT INTO rtc_revocations (tenant, user_id, at) VALUES ($1,$2,$3)`), tenant, user, at)
			if dbx.IsDuplicate(err) { // two nodes revoked the same user at once
				_, err = s.cfg.DB.ExecContext(ctx, s.rb(`UPDATE rtc_revocations SET at=$1 WHERE tenant=$2 AND user_id=$3`), at, tenant, user)
			}
		}
	}
	return s.hubs.closeUser(tenant, user, "revoked"), err
}

// ---------------------------------------------------------------------------
// Tickets, in the database.
// ---------------------------------------------------------------------------

type ticketWho struct {
	Tenant, User, Service string
	Scopes                auth.Scopes
	Expires               int64
	Issued                int64
}

func hashTicket(id string) string { h := sha256.Sum256([]byte(id)); return hex.EncodeToString(h[:]) }

func (s *Server) issueTicket(ctx context.Context, p auth.Principal) (string, error) {
	id := newTicketID()
	w := ticketWho{p.Tenant, p.User, p.Service, p.Scopes, 0, s.cfg.Now().UnixNano()}
	if !p.Expires.IsZero() {
		w.Expires = p.Expires.UnixNano()
	}
	b, _ := json.Marshal(w)
	// Only a hash of the ticket is stored: reading the table does not give a usable one.
	_, err := s.cfg.DB.ExecContext(ctx, s.rb(`INSERT INTO rtc_tickets (id, who, expires_at) VALUES ($1,$2,$3)`),
		hashTicket(id), string(b), s.cfg.Now().Add(ticketTTL).UnixNano())
	return id, err
}

// redeemTicket uses a ticket up. Two requests with the same ticket cannot both win:
// the delete reports whether this one removed the row.
func (s *Server) redeemTicket(ctx context.Context, id string) (auth.Principal, bool) {
	h := hashTicket(id)
	var who string
	var exp int64
	if err := s.cfg.DB.QueryRowContext(ctx, s.rb(`SELECT who, expires_at FROM rtc_tickets WHERE id=$1`), h).Scan(&who, &exp); err != nil {
		return auth.Principal{}, false
	}
	res, err := s.cfg.DB.ExecContext(ctx, s.rb(`DELETE FROM rtc_tickets WHERE id=$1`), h)
	if err != nil {
		return auth.Principal{}, false
	}
	if n, _ := res.RowsAffected(); n != 1 || s.cfg.Now().UnixNano() > exp {
		return auth.Principal{}, false
	}
	var w ticketWho
	// A user revoked after the ticket was issued gets nothing from it.
	if json.Unmarshal([]byte(who), &w) != nil || (w.Service == "" && s.auth.Revoked(w.Tenant, w.User, w.Issued)) {
		return auth.Principal{}, false
	}
	p := auth.Principal{Tenant: w.Tenant, User: w.User, Service: w.Service, Scopes: w.Scopes}
	if w.Expires != 0 {
		p.Expires = time.Unix(0, w.Expires)
	}
	return p, true
}

// ---------------------------------------------------------------------------
// Events between nodes.
// ---------------------------------------------------------------------------

// replicated says whether an event must reach other nodes. Media signaling
// belongs to the node that holds the room.
func replicated(event string) bool { return !strings.HasPrefix(event, "sfu.") }

func (s *Server) publish(tenant, user, event string, data json.RawMessage, from string) {
	if s.cfg.NodeID == "" || !replicated(event) {
		return
	}
	if len(data) == 0 {
		data = json.RawMessage("null")
	}
	select {
	case s.cl.q <- outEvent{tenant, user, event, from, data}:
	case <-time.After(2 * time.Second):
		s.record(audit.Event{Action: "cluster.publish", Outcome: audit.Failed, Code: "backlog_full"})
	case <-s.stop:
	}
}

type outRow struct {
	tenant, event, from string
	data                []byte
	users               []string
}

// flush writes a batch of events: consecutive ones with the same payload merge
// into one row addressed to several people, and the rows go in few statements.
func (c *cluster) flush(batch []outEvent) {
	// Events with the same payload share a row addressed to several people (one
	// message to a group is one row, not one per member), even when other events
	// arrived in between. Each person's own events must stay in order, so an event
	// joins an earlier row only if that person has nothing in a later row.
	var rows []outRow
	type slot struct {
		row   int
		users map[string]bool
	}
	byKey := map[string][]*slot{} // payload -> rows holding it
	lastRow := map[string]int{}   // tenant\x00user -> newest row with an event for them
	for _, e := range batch {
		pk := e.tenant + "\x00" + e.event + "\x00" + e.from + "\x00" + string(e.data)
		uk := e.tenant + "\x00" + e.user
		last, has := lastRow[uk]
		var into *slot
		for _, sl := range byKey[pk] {
			if !sl.users[e.user] && (!has || sl.row >= last) {
				into = sl
				break
			}
		}
		if into == nil {
			rows = append(rows, outRow{e.tenant, e.event, e.from, e.data, nil})
			into = &slot{row: len(rows) - 1, users: map[string]bool{}}
			byKey[pk] = append(byKey[pk], into)
		}
		into.users[e.user] = true
		rows[into.row].users = append(rows[into.row].users, e.user)
		if !has || into.row > last {
			lastRow[uk] = into.row
		}
	}
	at := c.s.cfg.Now().UnixMilli()
	for len(rows) > 0 {
		n := len(rows)
		if n > rowsPerStmt {
			n = rowsPerStmt
		}
		var sb strings.Builder
		sb.WriteString(`INSERT INTO rtc_outbox (node, tenant, users, event, sender, data, at) VALUES `)
		args := make([]any, 0, n*7)
		for i, r := range rows[:n] {
			if i > 0 {
				sb.WriteByte(',')
			}
			u, _ := json.Marshal(r.users)
			b := len(args)
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4, b+5, b+6, b+7)
			args = append(args, c.s.cfg.NodeID, r.tenant, string(u), r.event, r.from, string(r.data), at)
		}
		var err error
		for try := 0; try < 4; try++ {
			if _, err = c.s.cfg.DB.ExecContext(context.Background(), c.s.rb(sb.String()), args...); err == nil || !dbx.IsRetryable(err) {
				break
			}
			time.Sleep(time.Duration(try+1) * 20 * time.Millisecond)
		}
		if err != nil {
			c.s.record(audit.Event{Action: "cluster.publish", Outcome: audit.Failed, Code: "publish_failed", Meta: map[string]any{"error": err.Error(), "rows": n}})
		}
		rows = rows[n:]
	}
}

// writer is the node's only writer of the outbox.
func (c *cluster) writer() {
	defer c.s.wg.Done()
	for {
		var first outEvent
		select {
		case first = <-c.q:
		case <-c.s.stop:
			return
		}
		batch := []outEvent{first}
		timer := time.NewTimer(flushWait)
	gather:
		for len(batch) < flushMax {
			select {
			case e := <-c.q:
				batch = append(batch, e)
			case <-timer.C:
				break gather
			}
		}
		timer.Stop()
		c.flush(batch)
	}
}

type inRow struct {
	id                      int64
	node, tenant, users, ev string
	from, data              string
}

// poll reads what other nodes published. Ids are handed out in order but rows
// can become visible out of order when writers overlap (PostgreSQL, MySQL), so a
// hole in the numbers is looked for again for a few seconds before it is
// given up as a rolled-back write.
func (c *cluster) poll(ctx context.Context) {
	now := c.s.cfg.Now()
	q := `SELECT id, node, tenant, users, event, sender, data FROM rtc_outbox WHERE id>$1`
	args := []any{c.last}
	if len(c.gaps) > 0 {
		q += ` OR id IN (`
		i := 2
		for id, until := range c.gaps {
			if now.After(until) {
				delete(c.gaps, id)
				continue
			}
			if i > 2 {
				q += ","
			}
			q += fmt.Sprintf("$%d", i)
			args = append(args, id)
			i++
		}
		if i == 2 {
			q = strings.TrimSuffix(q, ` OR id IN (`)
		} else {
			q += ")"
		}
	}
	rows, err := c.s.cfg.DB.QueryContext(ctx, c.s.rb(q+` ORDER BY id`), args...)
	if err != nil {
		return
	}
	var list []inRow
	for rows.Next() {
		var e inRow
		if rows.Scan(&e.id, &e.node, &e.tenant, &e.users, &e.ev, &e.from, &e.data) == nil {
			list = append(list, e)
		}
	}
	rows.Close()
	for _, e := range list {
		if e.id <= c.last {
			delete(c.gaps, e.id) // a late row we were waiting for
		} else {
			for g := c.last + 1; g < e.id && len(c.gaps) < maxGaps; g++ {
				c.gaps[g] = now.Add(gapWait)
			}
			c.last = e.id
		}
		if e.node == c.s.cfg.NodeID {
			continue // ours: already delivered where it happened
		}
		var users []string
		if json.Unmarshal([]byte(e.users), &users) != nil {
			continue
		}
		for _, u := range users {
			_ = c.s.hubs.deliver(e.tenant, u, e.ev, json.RawMessage(e.data), e.from)
		}
		if strings.HasPrefix(e.ev, "group.") {
			c.s.dropConvs()
		}
	}
}

func (c *cluster) prune(ctx context.Context) {
	_, _ = c.s.cfg.DB.ExecContext(ctx, c.s.rb(`DELETE FROM rtc_outbox WHERE at<$1`), c.s.cfg.Now().Add(-outboxKeep).UnixMilli())
	_, _ = c.s.cfg.DB.ExecContext(ctx, c.s.rb(`DELETE FROM rtc_tickets WHERE expires_at<$1`), c.s.cfg.Now().UnixNano())
}

// run is the node's background loop for the shared state: one goroutine, so its
// queries never overlap.
func (c *cluster) run() {
	defer c.s.wg.Done()
	if c.s.cfg.NodeID != "" {
		c.s.wg.Add(1)
		go c.writer()
	}
	ev := time.NewTicker(pollEvery)
	rv := time.NewTicker(revokeEvery)
	pr := time.NewTicker(30 * time.Second)
	defer ev.Stop()
	defer rv.Stop()
	defer pr.Stop()
	ctx := context.Background()
	for {
		select {
		case <-ev.C:
			if c.s.cfg.NodeID != "" {
				c.poll(ctx)
			}
		case <-rv.C:
			_ = c.loadRevocations(ctx, true)
		case <-pr.C:
			c.prune(ctx)
		case <-c.s.stop:
			return
		}
	}
}

func newTicketID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return "rtct1." + hex.EncodeToString(b[:])
}

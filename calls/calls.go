// Package calls is the call state and signaling relay for audio and video
// calls, for both peer-to-peer calls and calls through an SFU.
//
// It carries no media. It decides who may call whom and who may signal whom,
// remembers the state of each call in SQL (so any node can answer for any
// call), and relays SDP and ICE between the participants as events on their
// private realtime topics. The sender of every relayed signal is stamped by the
// server, never taken from the message.
package calls

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oarkflow/rtcd/dbx"
	"strconv"
	"strings"
	"time"
)

// Errors.
var (
	ErrNotFound  = errors.New("calls: no such call")
	ErrForbidden = errors.New("calls: not allowed")
	ErrInvalid   = errors.New("calls: invalid request")
	ErrState     = errors.New("calls: the call is not in a state that allows this")
)

// Call states.
const (
	Ringing = "ringing"
	Active  = "active"
	Ended   = "ended"
)

// Modes.
const (
	P2P = "p2p" // media flows directly between two peers
	SFU = "sfu" // media flows through the server's selective forwarding unit
)

// Notifier delivers an event to one user of one tenant. It must not block: the
// store calls it while serving a request.
type Notifier interface {
	Notify(ctx context.Context, tenant, user, event string, data json.RawMessage, from string) error
}

// NotifierFunc adapts a function to Notifier.
type NotifierFunc func(ctx context.Context, tenant, user, event string, data json.RawMessage, from string) error

// Notify implements Notifier.
func (f NotifierFunc) Notify(ctx context.Context, tenant, user, event string, data json.RawMessage, from string) error {
	return f(ctx, tenant, user, event, data, from)
}

// Actor is the acting user.
type Actor struct{ ID, Tenant string }

// Participant is one user in a call.
type Participant struct {
	User  string `json:"user"`
	State string `json:"state"` // invited, joined, declined, left
}

// Call is a call and its participants.
type Call struct {
	ID           string        `json:"id"`
	Kind         string        `json:"kind"` // audio or video
	Mode         string        `json:"mode"`
	Initiator    string        `json:"initiator"`
	Tenant       string        `json:"tenant,omitempty"`
	Status       string        `json:"status"`
	Reason       string        `json:"reason,omitempty"`
	Room         string        `json:"room,omitempty"`  // SFU room, equal to the call id
	E2EE         bool          `json:"e2ee"`            // media is end-to-end encrypted: the server never holds the keys
	Group        string        `json:"group,omitempty"` // the group this call belongs to, if any
	CreatedAt    time.Time     `json:"created_at"`
	AnsweredAt   *time.Time    `json:"answered_at,omitempty"`
	EndedAt      *time.Time    `json:"ended_at,omitempty"`
	Participants []Participant `json:"participants"`
}

// ICEServer is one STUN or TURN server for a peer connection.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// ICEConfig describes the STUN/TURN servers handed to clients.
type ICEConfig struct {
	STUN []string
	TURN []string
	// Secret is the TURN server's shared secret (coturn "use-auth-secret").
	// Credentials derived from it expire; the secret itself never leaves.
	Secret string
	// TTL is how long a TURN credential is valid. Default 1h.
	TTL time.Duration
}

// Servers returns the ICE servers for a user at time now.
func (c ICEConfig) Servers(user string, now time.Time) []ICEServer {
	var out []ICEServer
	if len(c.STUN) > 0 {
		out = append(out, ICEServer{URLs: c.STUN})
	}
	if len(c.TURN) > 0 && c.Secret != "" {
		ttl := c.TTL
		if ttl <= 0 {
			ttl = time.Hour
		}
		username := strconv.FormatInt(now.Add(ttl).Unix(), 10) + ":" + user
		mac := hmac.New(sha1.New, []byte(c.Secret))
		mac.Write([]byte(username))
		out = append(out, ICEServer{URLs: c.TURN, Username: username, Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil))})
	}
	return out
}

// Options configure a Store.
type Options struct {
	Dialect  string
	Rebind   func(string) string
	Notifier Notifier
	ICE      ICEConfig
	// RingTimeout is how long a call rings before it counts as missed. Default 45s.
	RingTimeout time.Duration
	// MaxInvitees caps the people one call can invite. Default 20.
	MaxInvitees int
	// MaxRoomMembers caps the people a managed room (see OpenRoom) can admit. Default 1000.
	MaxRoomMembers int
	// RequireE2EE makes every call end-to-end encrypted; a call cannot be started
	// without it. (The server cannot make a browser encrypt, but it refuses the
	// server-side features that need plaintext and makes each client declare it.)
	RequireE2EE bool
	// CanCall, when set, is asked before a user may be called. Return an error
	// to refuse (blocked, different tenant, not a contact...).
	CanCall func(ctx context.Context, from Actor, to string) error
	// CacheTTL is how long a call read from the database is served from memory.
	// Mutations through this Store update it at once; the TTL only bounds how
	// stale a call can be if something else writes the database. Default 30s.
	CacheTTL time.Duration
	Now      func() time.Time
}

// Store keeps call state.
type Store struct {
	db     *sql.DB
	o      Options
	rebind func(string) string
	ignore string
	suffix string
	cache  *cache
}

// Open prepares the schema.
func Open(ctx context.Context, db *sql.DB, o Options) (*Store, error) {
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.RingTimeout <= 0 {
		o.RingTimeout = 45 * time.Second
	}
	if o.MaxInvitees <= 0 {
		o.MaxInvitees = 20
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 30 * time.Second
	}
	s := &Store{db: db, o: o, rebind: o.Rebind, cache: newCache(o.CacheTTL, o.Now)}
	if s.rebind == nil {
		s.rebind = func(q string) string { return q }
	}
	switch o.Dialect {
	case "mysql":
		s.ignore = "INSERT IGNORE INTO"
	case "sqlite":
		s.ignore = "INSERT OR IGNORE INTO"
	default:
		s.ignore, s.suffix = "INSERT INTO", " ON CONFLICT DO NOTHING"
	}
	key := "VARCHAR(191)"
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS rtc_calls (id ` + key + ` PRIMARY KEY, kind ` + key + ` NOT NULL, mode ` + key + ` NOT NULL,
			initiator ` + key + ` NOT NULL, tenant ` + key + ` NOT NULL DEFAULT '', status ` + key + ` NOT NULL,
			reason ` + key + ` NOT NULL DEFAULT '', created_at ` + key + ` NOT NULL, answered_at ` + key + ` NOT NULL DEFAULT '',
			ended_at ` + key + ` NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS rtc_participants (call_id ` + key + ` NOT NULL, user_id ` + key + ` NOT NULL,
			state ` + key + ` NOT NULL, PRIMARY KEY (call_id, user_id))`,
	} {
		if err := dbx.DDL(ctx, db, o.Dialect, q); err != nil {
			return nil, fmt.Errorf("calls: schema: %w", err)
		}
	}
	// A database made before end-to-end encryption existed has no such column.
	if _, err := db.ExecContext(ctx, `ALTER TABLE rtc_calls ADD COLUMN e2ee INTEGER NOT NULL DEFAULT 0`); err != nil {
		if m := strings.ToLower(err.Error()); !strings.Contains(m, "duplicate") && !strings.Contains(m, "exists") {
			return nil, fmt.Errorf("calls: schema: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE rtc_calls ADD COLUMN group_id `+key+` NOT NULL DEFAULT ''`); err != nil {
		if m := strings.ToLower(err.Error()); !strings.Contains(m, "duplicate") && !strings.Contains(m, "exists") {
			return nil, fmt.Errorf("calls: schema: %w", err)
		}
	}
	return s, nil
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "call_" + hex.EncodeToString(b)
}

// tsLayout is fixed-width, so timestamps compare correctly as strings in SQL;
// RFC3339Nano drops trailing zeros and does not.
const tsLayout = "2006-01-02T15:04:05.000000000Z"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	return &t
}

func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.rebind(q), args...)
}

// UserTopic names one user of one tenant. Two tenants may have a user with the
// same name; their events never meet.
func UserTopic(tenant, user string) string {
	if tenant == "" {
		return "user:" + user
	}
	return "user:" + tenant + "\x1f" + user
}

func (s *Store) tell(ctx context.Context, tenant, user, event string, v any, from string) {
	if s.o.Notifier == nil || user == "" || user == from {
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = s.o.Notifier.Notify(ctx, tenant, user, event, raw, from)
}

// ICE returns the ICE servers for a user.
func (s *Store) ICE(user string) []ICEServer { return s.o.ICE.Servers(user, s.o.Now()) }

// Start places a call. The caller is joined and every invitee is rung. The call
// is end-to-end encrypted if the store requires it (see Options.RequireE2EE).
func (s *Store) Start(ctx context.Context, by Actor, to []string, kind, mode string) (Call, error) {
	return s.StartCall(ctx, by, to, kind, mode, nil)
}

// StartCall is Start with an explicit choice about end-to-end encryption. nil
// takes the store's policy; false is refused when encryption is required.
func (s *Store) StartCall(ctx context.Context, by Actor, to []string, kind, mode string, e2ee *bool) (Call, error) {
	return s.StartWith(ctx, by, StartOptions{To: to, Kind: kind, Mode: mode, E2EE: e2ee})
}

// StartOptions describes a call to place.
type StartOptions struct {
	To   []string
	Kind string // audio or video
	Mode string // p2p or sfu
	E2EE *bool
	// Group, when set, makes this a call of that group. The caller must already
	// have checked that the actor belongs to it.
	Group string
}

// StartWith places a call.
func (s *Store) StartWith(ctx context.Context, by Actor, o StartOptions) (Call, error) {
	to, kind, mode, e2ee := o.To, o.Kind, o.Mode, o.E2EE
	if by.ID == "" {
		return Call{}, ErrForbidden
	}
	secure := s.o.RequireE2EE
	if e2ee != nil {
		if !*e2ee && s.o.RequireE2EE {
			return Call{}, fmt.Errorf("%w: this server only allows end-to-end encrypted calls", ErrInvalid)
		}
		secure = *e2ee
	}
	if kind != "audio" && kind != "video" {
		return Call{}, fmt.Errorf("%w: kind must be audio or video", ErrInvalid)
	}
	if mode != P2P && mode != SFU {
		return Call{}, fmt.Errorf("%w: mode must be p2p or sfu", ErrInvalid)
	}
	seen := map[string]bool{by.ID: true}
	var invitees []string
	for _, u := range to {
		if u = strings.TrimSpace(u); u != "" && !seen[u] {
			seen[u] = true
			invitees = append(invitees, u)
		}
	}
	switch {
	case len(invitees) == 0:
		return Call{}, fmt.Errorf("%w: nobody to call", ErrInvalid)
	case mode == P2P && len(invitees) != 1:
		return Call{}, fmt.Errorf("%w: a p2p call is between exactly two people; use mode sfu for a group", ErrInvalid)
	case len(invitees) > s.o.MaxInvitees:
		return Call{}, fmt.Errorf("%w: at most %d people can be invited", ErrInvalid, s.o.MaxInvitees)
	}
	for _, u := range invitees {
		if s.o.CanCall != nil {
			if err := s.o.CanCall(ctx, by, u); err != nil {
				return Call{}, fmt.Errorf("%w: %v", ErrForbidden, err)
			}
		}
	}
	now := s.o.Now()
	c := Call{ID: newID(), Kind: kind, Mode: mode, Initiator: by.ID, Tenant: by.Tenant, Status: Ringing, CreatedAt: now, E2EE: secure, Group: o.Group}
	if mode == SFU {
		c.Room = c.ID
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Call{}, err
	}
	defer tx.Rollback()
	e2eeBit := 0
	if secure {
		e2eeBit = 1
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_calls (id, kind, mode, initiator, tenant, status, created_at, e2ee, group_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`),
		c.ID, kind, mode, by.ID, by.Tenant, Ringing, ts(now), e2eeBit, o.Group); err != nil {
		return Call{}, err
	}
	c.Participants = append(c.Participants, Participant{by.ID, "joined"})
	for _, u := range append([]string{by.ID}, invitees...) {
		state := "invited"
		if u == by.ID {
			state = "joined"
		} else {
			c.Participants = append(c.Participants, Participant{u, state})
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_participants (call_id, user_id, state) VALUES ($1,$2,$3)`), c.ID, u, state); err != nil {
			return Call{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Call{}, err
	}
	for _, u := range invitees {
		s.tell(ctx, c.Tenant, u, "call.incoming", map[string]any{"call": c, "ice": s.ICE(u)}, by.ID)
	}
	return c, nil
}

// load reads a call, from memory when it is there, and expires it if it rang
// too long. The returned Call shares its participant list with the cache: it
// must not be modified. Use fresh after a write.
func (s *Store) load(ctx context.Context, id string) (Call, error) {
	if c, ok := s.cache.get(id); ok {
		if c.Status == Ringing && s.o.Now().Sub(c.CreatedAt) > s.o.RingTimeout {
			return s.finish(ctx, c, "missed", "")
		}
		return c, nil
	}
	return s.fresh(ctx, id)
}

// fresh reads a call from the database, bypassing and refilling the cache.
func (s *Store) fresh(ctx context.Context, id string) (Call, error) {
	s.cache.drop(id)
	var c Call
	var created, answered, ended string
	var e2eeBit int
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT id, kind, mode, initiator, tenant, status, reason, created_at, answered_at, ended_at, e2ee, group_id FROM rtc_calls WHERE id = $1`), id).
		Scan(&c.ID, &c.Kind, &c.Mode, &c.Initiator, &c.Tenant, &c.Status, &c.Reason, &created, &answered, &ended, &e2eeBit, &c.Group)
	c.E2EE = e2eeBit != 0
	if errors.Is(err, sql.ErrNoRows) {
		return Call{}, ErrNotFound
	}
	if err != nil {
		return Call{}, err
	}
	if t := parseTS(created); t != nil {
		c.CreatedAt = *t
	}
	c.AnsweredAt, c.EndedAt = parseTS(answered), parseTS(ended)
	if c.Mode == SFU {
		c.Room = c.ID
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT user_id, state FROM rtc_participants WHERE call_id = $1 ORDER BY user_id`), id)
	if err != nil {
		return Call{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var p Participant
		if err := rows.Scan(&p.User, &p.State); err != nil {
			return Call{}, err
		}
		c.Participants = append(c.Participants, p)
	}
	if err := rows.Err(); err != nil {
		return Call{}, err
	}
	if c.Status == Ringing && s.o.Now().Sub(c.CreatedAt) > s.o.RingTimeout {
		return s.finish(ctx, c, "missed", "")
	}
	s.cache.put(c)
	return c, nil
}

func (c Call) role(user string) (string, bool) {
	for _, p := range c.Participants {
		if p.User == user {
			return p.State, true
		}
	}
	return "", false
}

// get loads a call for an actor who is part of it. A stranger and an unknown
// id get the same answer, so ids cannot be probed.
func (s *Store) get(ctx context.Context, by Actor, id string) (Call, string, error) {
	c, err := s.load(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Call{}, "", ErrForbidden
		}
		return Call{}, "", err
	}
	state, ok := c.role(by.ID)
	if !ok || c.Tenant != by.Tenant {
		return Call{}, "", ErrForbidden
	}
	return c, state, nil
}

// Get returns a call the actor takes part in.
func (s *Store) Get(ctx context.Context, by Actor, id string) (Call, error) {
	c, _, err := s.get(ctx, by, id)
	return c, err
}

func (s *Store) setState(ctx context.Context, id, user, state string) error {
	_, err := s.exec(ctx, `UPDATE rtc_participants SET state = $1 WHERE call_id = $2 AND user_id = $3`, state, id, user)
	s.cache.drop(id)
	return err
}

// finish ends a call for everyone and tells them.
func (s *Store) finish(ctx context.Context, c Call, reason, by string) (Call, error) {
	if c.Status == Ended {
		return c, nil
	}
	now := s.o.Now()
	res, err := s.exec(ctx, `UPDATE rtc_calls SET status = $1, reason = $2, ended_at = $3 WHERE id = $4 AND status <> $5`, Ended, reason, ts(now), c.ID, Ended)
	s.cache.drop(c.ID)
	if err != nil {
		return c, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return s.reload(ctx, c.ID)
	}
	c.Status, c.Reason, c.EndedAt = Ended, reason, &now
	for _, p := range c.Participants {
		s.tell(ctx, c.Tenant, p.User, "call.ended", map[string]any{"call_id": c.ID, "reason": reason, "by": by}, by)
	}
	return c, nil
}

func (s *Store) reload(ctx context.Context, id string) (Call, error) { return s.fresh(ctx, id) }

// Answer accepts a ringing or active call. The first answer makes it active.
func (s *Store) Answer(ctx context.Context, by Actor, id string) (Call, error) {
	c, state, err := s.get(ctx, by, id)
	if err != nil {
		return Call{}, err
	}
	if c.Status == Ended {
		return c, ErrState
	}
	if state != "invited" {
		return Call{}, fmt.Errorf("%w: only an invited person can answer", ErrForbidden)
	}
	if err := s.setState(ctx, id, by.ID, "joined"); err != nil {
		return Call{}, err
	}
	if c.Status == Ringing {
		now := s.o.Now()
		_, _ = s.exec(ctx, `UPDATE rtc_calls SET status = $1, answered_at = $2 WHERE id = $3 AND status = $4`, Active, ts(now), id, Ringing)
		s.cache.drop(id)
	}
	c, err = s.fresh(ctx, id)
	if err != nil {
		return Call{}, err
	}
	for _, p := range c.Participants {
		s.tell(ctx, c.Tenant, p.User, "call.answered", map[string]any{"call_id": id, "user": by.ID, "ice": s.ICE(p.User)}, by.ID)
	}
	return c, nil
}

// Decline refuses a call. A declined p2p call ends; a declined group call goes
// on for the others, and ends if nobody is left to join.
func (s *Store) Decline(ctx context.Context, by Actor, id string) (Call, error) {
	c, state, err := s.get(ctx, by, id)
	if err != nil {
		return Call{}, err
	}
	if c.Status == Ended {
		return c, nil
	}
	if state != "invited" {
		return Call{}, fmt.Errorf("%w: only an invited person can decline", ErrForbidden)
	}
	if err := s.setState(ctx, id, by.ID, "declined"); err != nil {
		return Call{}, err
	}
	c, _ = s.fresh(ctx, id)
	for _, p := range c.Participants {
		s.tell(ctx, c.Tenant, p.User, "call.declined", map[string]any{"call_id": id, "user": by.ID}, by.ID)
	}
	if c.Mode == P2P || c.count("invited") == 0 && c.count("joined") <= 1 {
		return s.finish(ctx, c, "declined", by.ID)
	}
	return c, nil
}

func (c Call) count(state string) (n int) {
	for _, p := range c.Participants {
		if p.State == state {
			n++
		}
	}
	return
}

// End leaves a call. The initiator, and anyone in a p2p call, ends it for
// everyone; someone leaving a group call just leaves it, and the call ends
// when the last person goes.
func (s *Store) End(ctx context.Context, by Actor, id string) (Call, error) {
	c, state, err := s.get(ctx, by, id)
	if err != nil {
		return Call{}, err
	}
	if c.Status == Ended {
		return c, nil
	}
	if state == "declined" || state == "left" {
		return c, nil
	}
	if c.Managed() {
		return c, nil // leaving a managed room is leaving the SFU; the backend decides who is admitted and when it ends
	}
	if c.Mode == P2P || by.ID == c.Initiator {
		reason := "ended"
		if c.Status == Ringing {
			reason = "cancelled"
		}
		_ = s.setState(ctx, id, by.ID, "left")
		return s.finish(ctx, c, reason, by.ID)
	}
	if err := s.setState(ctx, id, by.ID, "left"); err != nil {
		return Call{}, err
	}
	c, _ = s.fresh(ctx, id)
	for _, p := range c.Participants {
		s.tell(ctx, c.Tenant, p.User, "call.left", map[string]any{"call_id": id, "user": by.ID}, by.ID)
	}
	if c.count("joined") == 0 {
		return s.finish(ctx, c, "ended", by.ID)
	}
	return c, nil
}

// Signal types a client may relay.
var signalTypes = map[string]bool{"offer": true, "answer": true, "candidate": true, "renegotiate": true, "mute": true, "unmute": true}

// MaxSignal is the largest signaling payload in bytes.
const MaxSignal = 16 << 10

// Signal relays an SDP or ICE message to another participant. The server sets
// the sender; the payload is opaque to it.
func (s *Store) Signal(ctx context.Context, by Actor, id, to, typ string, data json.RawMessage) error {
	if !signalTypes[typ] {
		return fmt.Errorf("%w: unknown signal type %q", ErrInvalid, typ)
	}
	if len(data) == 0 || len(data) > MaxSignal || !json.Valid(data) {
		return fmt.Errorf("%w: signal data must be JSON of at most %d bytes", ErrInvalid, MaxSignal)
	}
	c, state, err := s.get(ctx, by, id)
	if err != nil {
		return err
	}
	if c.Status == Ended {
		return ErrState
	}
	// The caller may send its offer while the call is still ringing.
	if state != "joined" && !(c.Status == Ringing && by.ID == c.Initiator) {
		return fmt.Errorf("%w: join the call before signaling", ErrForbidden)
	}
	if c.Mode != P2P {
		return fmt.Errorf("%w: signaling is relayed only for p2p calls; an sfu call signals the server", ErrInvalid)
	}
	peer, ok := c.role(to)
	if !ok || to == by.ID || peer == "declined" || peer == "left" {
		return fmt.Errorf("%w: %q is not in this call", ErrForbidden, to)
	}
	s.tell(ctx, c.Tenant, to, "call.signal", map[string]any{"call_id": id, "from": by.ID, "type": typ, "data": data}, by.ID)
	return nil
}

// MaxRelay is the largest end-to-end encryption message the server will carry.
const MaxRelay = 16 << 10

// Relay carries an opaque message from one participant to another and tells the
// recipient who sent it (the server sets the sender, never the message). It is
// how end-to-end key exchanges travel: the server cannot read, alter or forge
// them, only deliver or drop them. It works in both modes.
func (s *Store) Relay(ctx context.Context, by Actor, id, to, data string) error {
	if len(data) == 0 || len(data) > MaxRelay {
		return fmt.Errorf("%w: a message is 1 to %d bytes", ErrInvalid, MaxRelay)
	}
	c, state, err := s.get(ctx, by, id)
	if err != nil {
		return err
	}
	if c.Status == Ended {
		return ErrState
	}
	if state != "joined" && !(c.Status == Ringing && by.ID == c.Initiator) {
		return fmt.Errorf("%w: join the call before sending", ErrForbidden)
	}
	peer, ok := c.role(to)
	if !ok || to == by.ID || peer == "declined" || peer == "left" {
		return fmt.Errorf("%w: %q is not in this call", ErrForbidden, to)
	}
	raw, err := json.Marshal(map[string]any{"call_id": id, "from": by.ID, "data": data})
	if err != nil {
		return err
	}
	if s.o.Notifier != nil {
		return s.o.Notifier.Notify(ctx, c.Tenant, to, "call.e2ee", raw, by.ID)
	}
	return nil
}

// Sweep ends calls that rang past the timeout. Calls are also expired lazily
// when touched, so this only matters for callers who never look again; run it
// from a schedule.
func (s *Store) Sweep(ctx context.Context) (int, error) {
	cutoff := s.o.Now().Add(-s.o.RingTimeout)
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT id FROM rtc_calls WHERE status = $1 AND created_at < $2`), Ringing, ts(cutoff))
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	n := 0
	for _, id := range ids {
		if c, err := s.fresh(ctx, id); err == nil && c.Status == Ringing && s.o.Now().Sub(c.CreatedAt) > s.o.RingTimeout {
			if c, err = s.finish(ctx, c, "missed", ""); err == nil && c.Status == Ended {
				n++
			}
		} else if err == nil && c.Status == Ended {
			n++
		}
	}
	return n, nil
}

// View is what the relay paths need to know about a call and one participant,
// read without touching the database. Participants is shared with the cache and
// must not be modified.
type View struct {
	ID, Tenant, Mode, Status, Initiator, Group string
	E2EE                                       bool
	Managed                                    bool
	State                                      string // the actor's state: invited, joined, declined, left
	Participants                               []Participant
}

// Peek is Get for hot paths: it returns a View of a call the actor takes part
// in, from memory when it can.
func (s *Store) Peek(ctx context.Context, by Actor, id string) (View, error) {
	c, state, err := s.get(ctx, by, id)
	if err != nil {
		return View{}, err
	}
	return View{ID: c.ID, Tenant: c.Tenant, Mode: c.Mode, Status: c.Status, Initiator: c.Initiator, Group: c.Group,
		E2EE: c.E2EE, Managed: c.Managed(), State: state, Participants: c.Participants}, nil
}

// addParticipants rings users into a call that is not over. People who left or
// declined are rung again.
func (s *Store) addParticipants(ctx context.Context, c Call, users []string, by string) (Call, error) {
	for _, u := range users {
		if state, ok := c.role(u); ok {
			if state == "left" || state == "declined" {
				if err := s.setState(ctx, c.ID, u, "invited"); err != nil {
					return Call{}, err
				}
			}
			continue
		}
		if _, err := s.exec(ctx, s.ignore+` rtc_participants (call_id, user_id, state) VALUES ($1,$2,$3)`+s.suffix, c.ID, u, "invited"); err != nil {
			return Call{}, err
		}
	}
	s.cache.drop(c.ID)
	return s.fresh(ctx, c.ID)
}

// Invite adds people to a group call (mode sfu) that is under way. Any person
// who has joined may invite, up to the same cap as when the call began.
func (s *Store) Invite(ctx context.Context, by Actor, id string, users []string) (Call, error) {
	c, state, err := s.get(ctx, by, id)
	if err != nil {
		return Call{}, err
	}
	if c.Status == Ended {
		return Call{}, ErrState
	}
	if state != "joined" {
		return Call{}, fmt.Errorf("%w: join the call before inviting", ErrForbidden)
	}
	if c.Mode != SFU {
		return Call{}, fmt.Errorf("%w: a p2p call is between two people", ErrInvalid)
	}
	var add []string
	for _, u := range users {
		if u = strings.TrimSpace(u); u == "" || u == by.ID {
			continue
		}
		if st, ok := c.role(u); ok && st != "left" && st != "declined" {
			continue
		}
		if s.o.CanCall != nil {
			if err := s.o.CanCall(ctx, by, u); err != nil {
				return Call{}, fmt.Errorf("%w: %v", ErrForbidden, err)
			}
		}
		add = append(add, u)
	}
	if len(add) == 0 {
		return c, nil
	}
	if len(c.Participants)+len(add) > s.o.MaxInvitees+1 {
		return Call{}, fmt.Errorf("%w: at most %d people can be in a call", ErrInvalid, s.o.MaxInvitees+1)
	}
	c, err = s.addParticipants(ctx, c, add, by.ID)
	if err != nil {
		return Call{}, err
	}
	for _, u := range add {
		s.tell(ctx, c.Tenant, u, "call.incoming", map[string]any{"call": c, "ice": s.ICE(u)}, by.ID)
	}
	for _, p := range c.Participants {
		if p.State == "joined" {
			s.tell(ctx, c.Tenant, p.User, "call.invited", map[string]any{"call_id": id, "users": add, "by": by.ID}, by.ID)
		}
	}
	return c, nil
}

// ActiveGroupCall returns the call of a group that is not over, if there is one.
func (s *Store) ActiveGroupCall(ctx context.Context, tenant, group string) (Call, bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT id FROM rtc_calls WHERE tenant = $1 AND group_id = $2 AND status <> $3 ORDER BY created_at DESC LIMIT 1`),
		tenant, group, Ended).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Call{}, false, nil
	}
	if err != nil {
		return Call{}, false, err
	}
	c, err := s.load(ctx, id)
	if err != nil || c.Status == Ended {
		return Call{}, false, err
	}
	return c, true, nil
}

// JoinGroupCall rings a member of a group into the group's call. The caller has
// already checked that the actor belongs to the group.
func (s *Store) JoinGroupCall(ctx context.Context, by Actor, id string) (Call, error) {
	c, err := s.load(ctx, id)
	if err != nil {
		return Call{}, ErrForbidden
	}
	if c.Tenant != by.Tenant || c.Group == "" {
		return Call{}, ErrForbidden
	}
	if c.Status == Ended {
		return Call{}, ErrState
	}
	if st, ok := c.role(by.ID); ok && st != "left" && st != "declined" {
		return c, nil
	}
	if len(c.Participants)+1 > s.o.MaxInvitees+1 {
		return Call{}, fmt.Errorf("%w: at most %d people can be in a call", ErrInvalid, s.o.MaxInvitees+1)
	}
	return s.addParticipants(ctx, c, []string{by.ID}, by.ID)
}

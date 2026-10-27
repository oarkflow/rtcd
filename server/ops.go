package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/calls"
)

func jsonMarshal(v any) (json.RawMessage, error) { return json.Marshal(v) }

// session is one caller: a WebSocket connection, or one HTTP request.
type session struct {
	who       calls.Actor // the user acted as; empty ID for a service key not acting as a user
	service   string      // the service key's name, when a service is calling
	ip        string
	transport string // ws or http
	conn      string // the websocket connection id
	opened    time.Time

	scopes  atomic.Uint32
	expires atomic.Int64 // unix nano; zero means never
	mu      sync.Mutex
}

func newSession(p auth.Principal, ip, transport, conn string, now time.Time) *session {
	sess := &session{who: calls.Actor{ID: p.User, Tenant: p.Tenant}, service: p.Service, ip: ip, transport: transport, conn: conn, opened: now}
	sess.scopes.Store(uint32(p.Scopes))
	if !p.Expires.IsZero() {
		sess.expires.Store(p.Expires.UnixNano())
	}
	return sess
}

func (s *session) isService() bool { return s.service != "" }

func (s *session) allows(sc auth.Scopes) bool { return auth.Scopes(s.scopes.Load())&sc == sc }

func (s *session) expired(now time.Time) bool {
	e := s.expires.Load()
	return e != 0 && now.UnixNano() >= e
}

// opCtx is what an operation runs with.
type opCtx struct {
	context.Context
	s      *Server
	sess   *session
	target string         // the call or group acted on, for the audit entry
	meta   map[string]any // small facts for the audit entry; never message contents
}

func (o *opCtx) note(k string, v any) {
	if o.meta == nil {
		o.meta = map[string]any{}
	}
	o.meta[k] = v
}

func (o *opCtx) actor() calls.Actor { return o.sess.who }

// opDef describes one operation.
type opDef struct {
	name    string
	scope   auth.Scopes // what a token needs; zero means any signed-in caller
	service bool        // only a service key may call it
	// quiet operations are the constant background of a call (ICE candidates,
	// stats polls). A success is counted but not logged; a failure or refusal
	// always is. Everything else is logged whatever happens.
	quiet bool
	// relay operations carry messages between people and are limited per call.
	relay bool
	// maxBody overrides the default request size limit (64 KiB).
	maxBody int
	run     func(o *opCtx, raw json.RawMessage) (any, error)
}

func (s *Server) register(d opDef) { s.ops[d.name] = &d }

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, bad("the request is not valid JSON of the expected shape")
	}
	return v, nil
}

// exec is the one path every operation takes, from either transport.
func (s *Server) exec(ctx context.Context, sess *session, name string, raw json.RawMessage) (out any, err error) {
	d := s.ops[name]
	o := &opCtx{Context: ctx, s: s, sess: sess}
	now := s.cfg.Now()
	defer func() {
		switch {
		case err == nil:
			s.opsOK.Add(1)
		default:
			status, _, _ := classify(err)
			if outcomeOf(status) == audit.Denied {
				s.opsDenied.Add(1)
			} else {
				s.opsFailed.Add(1)
			}
		}
		if d != nil && d.quiet && err == nil {
			return
		}
		s.auditOp(o, name, err, now)
	}()
	switch {
	case d == nil:
		return nil, &apiError{404, "unknown_operation", ""}
	case sess.expired(now):
		return nil, unauth("token_expired")
	case d.service && !sess.isService():
		return nil, denied("service_key_required")
	case d.scope != 0 && !sess.allows(d.scope):
		return nil, denied("scope_missing")
	case !d.service && sess.who.ID == "":
		return nil, &apiError{400, "user_required", "a service names the user it acts for in X-RTC-User"}
	}
	key := sess.who.Tenant + "\x00" + sess.who.ID + "\x00" + sess.service
	if !s.opLimit.allow(key, now) {
		return nil, &apiError{429, "rate_limited", ""}
	}
	if len(raw) > d.bodyLimit() {
		return nil, &apiError{413, "too_large", ""}
	}
	return d.run(o, raw)
}

const maxBody = 64 << 10

func (d *opDef) bodyLimit() int {
	if d != nil && d.maxBody > 0 {
		return d.maxBody
	}
	return maxBody
}

// relayAllowed applies the per-call limit for operations that carry messages
// between people, so one participant cannot flood another's connection.
func (o *opCtx) relayAllowed(call string) error {
	k := o.sess.who.Tenant + "\x00" + o.sess.who.ID + "\x00" + call
	if !o.s.rlLimit.allow(k, o.s.cfg.Now()) {
		return &apiError{429, "rate_limited", "too many messages in this call"}
	}
	return nil
}

// auditOp records an operation and its outcome.
func (s *Server) auditOp(o *opCtx, name string, err error, at time.Time) {
	if err != nil {
		if _, code, _ := classify(err); code == "rate_limited" {
			// A client told to slow down and retrying would otherwise write an entry
			// per retry and fill the log (and stall everyone behind it). The refusals
			// are counted and written as one entry per user and operation every few
			// seconds.
			if !s.limited.note(o.sess.who.Tenant, o.sess.who.ID, o.sess.service, name, o.sess.ip, o.sess.transport) {
				return // not the first since the last flush: counted, written with the next summary
			}
		}
	}
	e := audit.Event{Tenant: o.sess.who.Tenant, Time: at, Actor: o.sess.who.ID, Service: o.sess.service, Action: name,
		Target: o.target, Outcome: audit.OK, IP: o.sess.ip, Transport: o.sess.transport, Conn: o.sess.conn, Meta: o.meta}
	if err != nil {
		status, code, _ := classify(err)
		e.Outcome, e.Code = outcomeOf(status), code
	}
	s.record(e)
}

// record puts an entry in the audit log. If the log cannot take it the entry is
// not lost silently: it is counted and written to standard error.
func (s *Server) record(e audit.Event) {
	if err := s.Audit.Record(e); err != nil {
		s.auditRefused.Add(1)
		b, _ := json.Marshal(e)
		fmt.Fprintf(os.Stderr, "rtcd: AUDIT NOT RECORDED (%v): %s\n", err, b)
	}
}

// auditAnon records a failure that cannot be tied to a tenant, within a budget
// so an attacker cannot fill the log.
func (s *Server) auditAnon(action, code, ip, transport string) {
	if !s.anonFail.allow(s.cfg.Now()) {
		s.anonSuppressed.Add(1)
		return
	}
	s.record(audit.Event{Action: action, Outcome: audit.Denied, Code: code, IP: ip, Transport: transport})
}

func contextWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}

// limitedLog aggregates rate-limit refusals.
type limitedLog struct {
	mu sync.Mutex
	m  map[string]*limitedEntry
}

type limitedEntry struct {
	tenant, user, service, op, ip, transport string
	n                                        int
}

// note counts a refusal and reports whether it is the first since the last flush.
func (l *limitedLog) note(tenant, user, service, op, ip, transport string) bool {
	k := tenant + "\x00" + user + "\x00" + service + "\x00" + op
	l.mu.Lock()
	if l.m == nil {
		l.m = map[string]*limitedEntry{}
	}
	e := l.m[k]
	if e == nil {
		if len(l.m) >= 10000 { // bounded: an attacker with many identities cannot grow it
			l.mu.Unlock()
			return false
		}
		e = &limitedEntry{tenant: tenant, user: user, service: service, op: op, ip: ip, transport: transport}
		l.m[k] = e
	}
	e.n++
	l.mu.Unlock()
	return e.n == 1
}

// flush writes one audit entry per user and operation that was refused.
func (s *Server) flushLimited() {
	s.limited.mu.Lock()
	m := s.limited.m
	s.limited.m = nil
	s.limited.mu.Unlock()
	for _, e := range m {
		if e.n > 1 { // the first was written when it happened
			s.record(audit.Event{Tenant: e.tenant, Actor: e.user, Service: e.service, Action: e.op, Outcome: audit.Denied, Code: "rate_limited",
				IP: e.ip, Transport: e.transport, Meta: map[string]any{"refused": e.n - 1, "further": true}})
		}
	}
}

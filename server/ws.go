package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/fh"
	ws "github.com/oarkflow/fh/pkg/websocket"
	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/auth"
)

// The WebSocket is the service's main interface. One connection carries a
// user's requests (an envelope with an id and the name of an operation, answered
// by an "ack" or "error" with the same id), and every event pushed to them (an
// envelope of type "emit").
//
// Connections are spread over independent shards, each its own fh EventHub with
// its own lock, and each user's connections live in exactly one shard. Pushing
// an event to a user takes one shard's read lock for one map lookup and then
// queues the frame on each of that user's connections without holding it, so
// delivery to different users never contends, and neither does connecting or
// disconnecting on another shard.
type hubs struct {
	s          *Server
	shards     []*shard
	pending    sync.Map // connection id -> *session, between the upgrade and OnConnect
	conns      atomic.Int64
	sent       atomic.Int64
	dropped    atomic.Int64
	slowClosed atomic.Int64
	tenants    sync.Map // tenant -> *atomic.Int64, connections open on this node
	cfg        ws.Config
}

type shard struct {
	h       *hubs
	hub     *ws.EventHub
	handler fh.HandlerFunc
	mu      sync.RWMutex
	users   map[string][]*conn // user key -> connections; the slices are replaced, never edited
	byID    map[string]*conn
}

type conn struct {
	ec     *ws.EventConn
	sess   *session
	key    string
	ctx    context.Context
	cancel context.CancelFunc
	shard  *shard
	slow   atomic.Bool // set once the connection is being closed for not keeping up
}

func userKey(tenant, user string) string { return tenant + "\x00" + user }

func newHubs(s *Server) *hubs {
	h := &hubs{s: s}
	cfg := ws.DefaultConfig()
	cfg.MaxMessageSize = 256 << 10 // the largest message is a server offer or a key message
	cfg.PingInterval = 25 * time.Second
	cfg.PongTimeout = 75 * time.Second
	// fh closes a connection that sends more than this many messages a second.
	// That is the backstop for abuse; our own per-user limit is lower, answers
	// "rate_limited" and keeps the connection, and is what normal clients meet.
	cfg.MaxMessagesPerSecond = int(math.Max(1000, 2*s.cfg.OpsBurst))
	cfg.CheckOrigin = func(c fh.Ctx) bool {
		o := c.Get("Origin")
		if o == "" {
			return true // not a browser
		}
		if u, err := url.Parse(o); err == nil && strings.EqualFold(u.Host, c.Get("Host")) {
			return true
		}
		return s.originAllowed(o)
	}
	h.cfg = cfg
	for i := 0; i < s.cfg.Shards; i++ {
		sh := &shard{h: h, users: map[string][]*conn{}, byID: map[string]*conn{}}
		hcfg := ws.EventHubConfig{
			WriterQueueSize: s.cfg.WriterQueue, MaxEnvelopeBytes: 256 << 10, MaxPayloadBytes: 192 << 10,
			ClientIdleTimeout: 5 * time.Minute, CleanupInterval: 30 * time.Second, MaxSubscriptions: 1,
			CloseSlowClient: true, EnablePresence: false, SendHello: false,
			// Clients never subscribe or publish to topics: the server addresses
			// events to people. Only requests (emit) are allowed.
			Authorize: func(_ *ws.EventConn, action, topic, channel string) error {
				if action != ws.ActionEmit || topic != "" || channel != "" {
					return ws.ErrEventForbidden
				}
				return nil
			},
			ClientID:     func(_ fh.Ctx, meta map[string]string) string { return meta["sid"] },
			OnConnect:    sh.attach,
			OnDisconnect: sh.detach,
		}
		sh.hub = ws.NewEventHub(hcfg)
		wcfg := cfg
		wcfg.Manager = ws.NewManager()
		wcfg.Manager.MaxConnections = s.cfg.MaxConnections // the real cap is checked in upgrade
		sh.handler = ws.NewEventHandler(sh.hub, wcfg, func(c fh.Ctx) map[string]string {
			sid, _ := c.Locals("rtcd.sid").(string)
			return map[string]string{"sid": sid}
		})
		h.shards = append(h.shards, sh)
	}
	return h
}

// bind makes every operation callable over the WebSocket.
func (h *hubs) bind() {
	for _, sh := range h.shards {
		for name := range h.s.ops {
			sh.hub.On(name, sh.handle(name))
		}
	}
}

func (h *hubs) close() {
	for _, sh := range h.shards {
		_ = sh.hub.Close()
	}
}

func (h *hubs) shardFor(key string) *shard { return h.shards[fnv32(key)%uint32(len(h.shards))] }

func (h *hubs) tenantCount(t string) *atomic.Int64 {
	v, _ := h.tenants.LoadOrStore(t, new(atomic.Int64))
	return v.(*atomic.Int64)
}

func (h *hubs) count() int { return int(h.conns.Load()) }

func (h *hubs) counters() (sent, dropped int64) { return h.sent.Load(), h.dropped.Load() }

func (sh *shard) handle(name string) ws.Handler {
	return func(hc *ws.HandlerContext) (any, error) {
		sh.mu.RLock()
		c := sh.byID[hc.Conn.ID]
		sh.mu.RUnlock()
		if c == nil {
			return nil, ws.ErrEventClosed
		}
		ctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
		defer cancel()
		res, err := sh.h.s.exec(ctx, c.sess, name, hc.Payload)
		if err != nil {
			_, code, msg := classify(err)
			if msg != "" {
				return nil, errors.New(code + ": " + msg)
			}
			return nil, errors.New(code)
		}
		if res == nil {
			res = map[string]bool{"ok": true}
		}
		return res, nil
	}
}

// attach registers a connection once the hub has accepted it.
func (sh *shard) attach(ec *ws.EventConn) {
	v, ok := sh.h.pending.LoadAndDelete(ec.ID)
	if !ok {
		_ = ec.Close(ws.ClosePolicyViolation, "no session")
		return
	}
	sess := v.(*session)
	ctx, cancel := context.WithCancel(context.Background())
	c := &conn{ec: ec, sess: sess, key: userKey(sess.who.Tenant, sess.who.ID), ctx: ctx, cancel: cancel, shard: sh}
	sh.mu.Lock()
	sh.byID[ec.ID] = c
	sh.users[c.key] = append(append([]*conn(nil), sh.users[c.key]...), c)
	sh.mu.Unlock()
	sh.h.conns.Add(1)
	sh.h.tenantCount(sess.who.Tenant).Add(1)
	exp := ""
	if e := sess.expires.Load(); e != 0 {
		exp = time.Unix(0, e).UTC().Format(time.RFC3339)
	}
	_ = ec.Emit("ready", map[string]any{"user": sess.who.ID, "tenant": sess.who.Tenant, "conn": ec.ID, "expires_at": exp, "scopes": auth.Scopes(sess.scopes.Load()).Names()})
	sh.h.s.record(audit.Event{Tenant: sess.who.Tenant, Actor: sess.who.ID, Service: sess.service, Action: "ws.open", Outcome: audit.OK, IP: sess.ip, Transport: "ws", Conn: ec.ID})
}

func (sh *shard) detach(ec *ws.EventConn, cause error) {
	sh.mu.Lock()
	c := sh.byID[ec.ID]
	delete(sh.byID, ec.ID)
	if c != nil {
		var rest []*conn
		for _, x := range sh.users[c.key] {
			if x != c {
				rest = append(rest, x)
			}
		}
		if len(rest) == 0 {
			delete(sh.users, c.key)
		} else {
			sh.users[c.key] = rest
		}
	}
	sh.mu.Unlock()
	if c == nil {
		return
	}
	c.cancel()
	sh.h.conns.Add(-1)
	sh.h.tenantCount(c.sess.who.Tenant).Add(-1)
	meta := map[string]any{"seconds": int(sh.h.s.cfg.Now().Sub(c.sess.opened).Seconds())}
	if cause != nil {
		meta["cause"] = cause.Error()
	}
	sh.h.s.record(audit.Event{Tenant: c.sess.who.Tenant, Actor: c.sess.who.ID, Service: c.sess.service, Action: "ws.close", Outcome: audit.OK, IP: c.sess.ip, Transport: "ws", Conn: ec.ID, Meta: meta})
}

// deliver pushes an event to every connection of one user on this node.
func (h *hubs) deliver(tenant, user, event string, data json.RawMessage, from string) error {
	key := userKey(tenant, user)
	sh := h.shardFor(key)
	sh.mu.RLock()
	list := sh.users[key] // never edited in place, so it is safe to use after unlocking
	sh.mu.RUnlock()
	if len(list) == 0 {
		return nil
	}
	frame := encodeEvent(event, data, from, h.s.cfg.Now())
	msg := ws.OutboundMessage{Opcode: ws.Text, Payload: frame} // one buffer, shared: writers only read it
	for _, c := range list {
		// Queue the frame without ever waiting, and without calling Writer.Send:
		// when its queue is full Send closes the connection on the spot, and that
		// close writes to the very socket that is not draining, which can stall
		// the caller for the write timeout. The caller here is someone else's
		// request. A connection that cannot keep up is closed from its own goroutine.
		w := c.ec.Writer
		select {
		case <-w.Done:
			continue
		default:
		}
		select {
		case w.Queue <- msg:
			h.sent.Add(1)
		default:
			h.dropped.Add(1)
			if c.slow.CompareAndSwap(false, true) {
				h.slowClosed.Add(1)
				go func(c *conn) {
					h.s.record(audit.Event{Tenant: c.sess.who.Tenant, Actor: c.sess.who.ID, Action: "ws.slow_client", Outcome: audit.Denied, Code: "slow_client", IP: c.sess.ip, Transport: "ws", Conn: c.ec.ID})
					_ = c.ec.Close(ws.ClosePolicyViolation, "slow client")
				}(c)
			}
		}
	}
	return nil
}

// encodeEvent builds the envelope once for all recipients.
func encodeEvent(event string, data json.RawMessage, from string, at time.Time) []byte {
	b := make([]byte, 0, len(data)+96)
	b = append(b, `{"type":"emit","event":`...)
	b = strconv.AppendQuote(b, event) // event names are fixed identifiers, so Go and JSON quoting agree
	b = append(b, `,"payload":`...)
	if len(data) == 0 {
		b = append(b, "null"...)
	} else {
		b = append(b, data...)
	}
	if from != "" {
		fj, _ := json.Marshal(from)
		b = append(b, `,"from":`...)
		b = append(b, fj...)
	}
	b = append(b, `,"ts":`...)
	b = strconv.AppendInt(b, at.UnixMilli(), 10)
	return append(b, '}')
}

// expire closes connections whose tokens have run out and were not refreshed.
func (h *hubs) expire(now time.Time) {
	for _, sh := range h.shards {
		var gone []*conn
		sh.mu.RLock()
		for _, c := range sh.byID {
			if c.sess.expired(now) {
				gone = append(gone, c)
			}
		}
		sh.mu.RUnlock()
		for _, c := range gone {
			h.s.record(audit.Event{Tenant: c.sess.who.Tenant, Actor: c.sess.who.ID, Action: "ws.expired", Outcome: audit.Denied, Code: "token_expired", IP: c.sess.ip, Transport: "ws", Conn: c.ec.ID})
			_ = c.ec.Close(ws.ClosePolicyViolation, "token expired")
		}
	}
}

// originAllowed reports whether a browser page at origin may connect.
func (s *Server) originAllowed(origin string) bool {
	for _, a := range s.cfg.AllowedOrigins {
		if a == "*" || strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}

// upgrade authenticates a request and hands it to its shard's hub.
func (s *Server) upgrade(c fh.Ctx) error {
	ip := strings.Clone(c.IP())
	p, err := s.identify(c, true, ip, "ws")
	if err != nil {
		return writeError(c, err)
	}
	if p.IsService() && p.User == "" {
		if p, err = p.WithUser(strings.Clone(c.Get("X-RTC-User"))); err != nil {
			return writeError(c, &apiError{400, "user_required", "a service names the user it acts for in X-RTC-User"})
		}
	}
	key := userKey(p.Tenant, p.User)
	sh := s.hubs.shardFor(key)
	if int(s.hubs.conns.Load()) >= s.cfg.MaxConnections {
		return writeError(c, &apiError{503, "server_full", ""})
	}
	if m := s.cfg.MaxConnsPerTenant; m > 0 && int(s.hubs.tenantCount(p.Tenant).Load()) >= m {
		s.record(audit.Event{Tenant: p.Tenant, Actor: p.User, Service: p.Service, Action: "ws.open", Outcome: audit.Denied, Code: "tenant_full", IP: ip, Transport: "ws"})
		return writeError(c, &apiError{429, "tenant_full", ""})
	}
	sh.mu.RLock()
	n := len(sh.users[key])
	sh.mu.RUnlock()
	if n >= s.cfg.MaxConnsPerUser {
		s.record(audit.Event{Tenant: p.Tenant, Actor: p.User, Service: p.Service, Action: "ws.open", Outcome: audit.Denied, Code: "too_many_connections", IP: ip, Transport: "ws"})
		return writeError(c, &apiError{429, "too_many_connections", ""})
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	sid := hex.EncodeToString(id[:])
	s.hubs.pending.Store(sid, newSession(p, ip, "ws", sid, s.cfg.Now()))
	defer s.hubs.pending.Delete(sid)
	c.Locals("rtcd.sid", sid)
	return sh.handler(c)
}

// connectedAmong returns those of users (but not except) that have a live
// connection to this node.
func (h *hubs) connectedAmong(tenant string, users []string, except string) []string {
	var out []string
	for _, u := range users {
		if u == except {
			continue
		}
		key := userKey(tenant, u)
		sh := h.shardFor(key)
		sh.mu.RLock()
		n := len(sh.users[key])
		sh.mu.RUnlock()
		if n > 0 {
			out = append(out, u)
		}
	}
	return out
}

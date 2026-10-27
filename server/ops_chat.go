package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/chat"
	"github.com/oarkflow/rtcd/groups"
)

// A conversation is a group: whoever is in the group may send to it and read it,
// and nobody else. A direct message is a group of two.

type convInfo struct {
	members []string
	admin   map[string]bool
	member  map[string]bool
	at      time.Time
}

// The cache is split over shards so that conversations do not share a lock, and
// a miss is loaded once however many requests arrive at the same moment.
const convShards = 32

type convShard struct {
	mu     sync.Mutex
	gen    uint64 // bumped by every drop, so a read that raced a change is not kept
	m      map[string]*convInfo
	flight map[string]*flightCall
}

type convCache [convShards]convShard

type flightCall struct {
	gen  uint64
	done chan struct{}
	ci   *convInfo
	err  error
}

const convTTL = 5 * time.Second

func (c *convCache) shard(key string) *convShard { return &c[fnv32(key)%convShards] }

func (s *Server) initConvs() {
	for i := range s.convs {
		s.convs[i].m = map[string]*convInfo{}
		s.convs[i].flight = map[string]*flightCall{}
	}
}

// conv returns who is in a conversation, for a caller who must be one of them.
// The answer is held for a few seconds, and dropped at once by any change to a
// group on this node (or, on another node, within the poll interval), so a
// removed member cannot keep sending. The roster is one query, and requests
// that miss together wait for one load instead of each making their own.
func (s *Server) conv(o *opCtx, id string) (*convInfo, error) {
	tenant := o.sess.who.Tenant
	key := tenant + "\x00" + id
	sh := s.convs.shard(key)
	now := s.cfg.Now()
	for {
		sh.mu.Lock()
		if ci := sh.m[key]; ci != nil && now.Sub(ci.at) <= convTTL {
			sh.mu.Unlock()
			return s.member(ci, o)
		}
		if fl := sh.flight[key]; fl != nil && fl.gen == sh.gen { // a load that began before a change may be stale
			sh.mu.Unlock()
			select {
			case <-fl.done:
			case <-o.Done():
				return nil, o.Err()
			}
			if fl.err != nil {
				return nil, fl.err
			}
			return s.member(fl.ci, o)
		}
		gen := sh.gen
		fl := &flightCall{gen: gen, done: make(chan struct{})}
		sh.flight[key] = fl
		sh.mu.Unlock()

		list, err := s.Groups.Roster(context.WithoutCancel(o), tenant, id)
		if err == nil {
			fl.ci = &convInfo{admin: map[string]bool{}, member: map[string]bool{}, at: now}
			for _, m := range list {
				fl.ci.members = append(fl.ci.members, m.User)
				fl.ci.member[m.User] = true
				if m.Role == "owner" || m.Role == "admin" {
					fl.ci.admin[m.User] = true
				}
			}
		}
		fl.err = err
		sh.mu.Lock()
		if sh.flight[key] == fl {
			delete(sh.flight, key)
		}
		if err == nil && sh.gen == gen && len(list) > 0 {
			if len(sh.m) > 4000 {
				sh.m = map[string]*convInfo{}
			}
			sh.m[key] = fl.ci
		}
		sh.mu.Unlock()
		close(fl.done)
		if err != nil {
			return nil, err
		}
		return s.member(fl.ci, o)
	}
}

// member is the answer a stranger gets: the same as for a group that does not exist.
func (s *Server) member(ci *convInfo, o *opCtx) (*convInfo, error) {
	if ci == nil || !ci.member[o.sess.who.ID] {
		return nil, groups.ErrForbidden
	}
	return ci, nil
}

func (s *Server) dropConvs() {
	for i := range s.convs {
		sh := &s.convs[i]
		sh.mu.Lock()
		sh.m = map[string]*convInfo{}
		sh.gen++
		sh.mu.Unlock()
	}
}

func (s *Server) tellConv(tenant string, ci *convInfo, event string, v any, from string) {
	raw, err := jsonMarshal(v)
	if err != nil {
		return
	}
	for _, u := range ci.members {
		_ = s.Notify(context.Background(), tenant, u, event, raw, from)
	}
}

func (s *Server) registerChat() {
	msg := func(name string, run func(o *opCtx, raw json.RawMessage) (any, error)) {
		s.register(opDef{name: "msg." + name, scope: auth.ScopeChat, run: run})
	}
	// msg.send {conv, id, body, epoch, ttl}: body is opaque (the client encrypts
	// it). epoch is the key generation it was sealed under, and must be the
	// conversation's current one (0 for a conversation that has none). ttl, in
	// seconds, makes the message disappear. The answer carries the number the
	// message was given; every member, the sender's other devices included, gets
	// msg.new.
	s.register(opDef{name: "msg.send", scope: auth.ScopeChat, relay: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv  string `json:"conv"`
			ID    string `json:"id"`
			Body  string `json:"body"`
			Epoch int64  `json:"epoch"`
			TTL   int64  `json:"ttl"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		tenant, me := o.sess.who.Tenant, o.sess.who.ID
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		o.note("bytes", len(in.Body)) // the size only; the body is ciphertext
		if in.TTL < 0 || in.TTL > int64(chat.MaxTTL/time.Second) {
			return nil, bad("ttl is 0 to 366 days, in seconds")
		}
		st, err := s.Chat.State(o, tenant, in.Conv)
		if err != nil {
			return nil, err
		}
		if st, err = s.epochOK(o, tenant, in.Conv, st, in.Epoch); err != nil {
			return nil, err
		}
		if err := o.relayAllowed(in.Conv); err != nil {
			return nil, err
		}
		if !s.convLimit.allow(tenant+"\x00"+in.Conv, s.cfg.Now()) {
			return nil, &apiError{429, "rate_limited", "this conversation is receiving messages faster than its members can be sent them"}
		}
		ttl := time.Duration(in.TTL) * time.Second
		if ttl == 0 {
			ttl = st.TTL
		}
		m, dup, err := s.Chat.Send(o, chat.SendIn{Tenant: tenant, Conv: in.Conv, Sender: me, ID: in.ID, Body: in.Body, Epoch: in.Epoch, TTL: ttl})
		if err != nil {
			return nil, err
		}
		if dup {
			o.note("duplicate", true)
			return map[string]any{"seq": m.Seq, "sent_at": m.Sent, "duplicate": true}, nil
		}
		s.tellConv(tenant, ci, "msg.new", m, me)
		if s.hook.enabled() {
			s.hook.emit(HookEvent{Type: "msg.new", Tenant: tenant, Conv: in.Conv, Seq: m.Seq, Msg: in.ID, Sender: me, Size: len(in.Body), Epoch: in.Epoch,
				Recipients: without(ci.members, me), Connected: s.hubs.connectedAmong(tenant, ci.members, me)})
		}
		out := map[string]any{"seq": m.Seq, "sent_at": m.Sent}
		if m.Expires != nil {
			out["expires_at"] = m.Expires
		}
		return out, nil
	}})
	msg("history", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv   string `json:"conv"`
			After  int64  `json:"after"`
			Before int64  `json:"before"`
			Limit  int    `json:"limit"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		if _, err := s.conv(o, in.Conv); err != nil {
			return nil, err
		}
		list, err := s.Chat.History(o, o.sess.who.Tenant, in.Conv, in.After, in.Before, in.Limit)
		return map[string]any{"messages": list}, err
	})
	msg("read", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv string `json:"conv"`
			Seq  int64  `json:"seq"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		if in.Seq <= 0 {
			return nil, bad("seq is required")
		}
		seq, err := s.Chat.MarkRead(o, o.sess.who.Tenant, in.Conv, o.sess.who.ID, in.Seq)
		if err == nil {
			s.tellConv(o.sess.who.Tenant, ci, "msg.read", map[string]any{"conv": in.Conv, "seq": seq}, o.sess.who.ID)
		}
		return map[string]any{"seq": seq}, err
	})
	msg("delete", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv string `json:"conv"`
			Seq  int64  `json:"seq"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		st, err := s.Chat.State(o, o.sess.who.Tenant, in.Conv)
		if err != nil {
			return nil, err
		}
		window := st.DeleteWindow
		if window == 0 {
			window = s.cfg.DeleteWindow
		}
		if err := s.Chat.Delete(o, o.sess.who.Tenant, in.Conv, in.Seq, o.sess.who.ID, ci.admin[o.sess.who.ID], window); err != nil {
			return nil, err
		}
		s.tellConv(o.sess.who.Tenant, ci, "msg.deleted", map[string]any{"conv": in.Conv, "seq": in.Seq}, o.sess.who.ID)
		if s.hook.enabled() {
			s.hook.emit(HookEvent{Type: "msg.deleted", Tenant: o.sess.who.Tenant, Conv: in.Conv, Seq: in.Seq, Sender: o.sess.who.ID, Recipients: without(ci.members, o.sess.who.ID)})
		}
		return nil, nil
	})
	// msg.typing {conv}: tells the other members this one is typing. Nothing is
	// stored; at most a few a second are sent, and the rest are dropped quietly.
	s.register(opDef{name: "msg.typing", scope: auth.ScopeChat, quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv string `json:"conv"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		me, tenant := o.sess.who.ID, o.sess.who.Tenant
		if !s.typing.allow(tenant+"\x00"+in.Conv+"\x00"+me, s.cfg.Now()) {
			return nil, nil
		}
		raw, _ = jsonMarshal(map[string]any{"conv": in.Conv, "user": me})
		for _, u := range ci.members {
			if u != me {
				_ = s.Notify(context.Background(), tenant, u, "msg.typing", raw, me)
			}
		}
		return nil, nil
	}})
	// msg.cursors {conv}: every member's read position.
	msg("cursors", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv string `json:"conv"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		if _, err := s.conv(o, in.Conv); err != nil {
			return nil, err
		}
		list, err := s.Chat.Cursors(o, o.sess.who.Tenant, in.Conv)
		return map[string]any{"cursors": list}, err
	})
	// msg.summary {convs}: for each conversation of the caller's, the newest
	// message and the caller's read position and unread count. Conversations the
	// caller is not in are left out.
	s.register(opDef{name: "msg.summary", scope: auth.ScopeChat, quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Convs []string `json:"convs"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if len(in.Convs) == 0 || len(in.Convs) > 100 {
			return nil, bad("name 1 to 100 conversations")
		}
		var mine []string
		for _, c := range in.Convs {
			if _, err := s.conv(o, c); err == nil {
				mine = append(mine, c)
			}
		}
		list, err := s.Chat.Summaries(o, o.sess.who.Tenant, o.sess.who.ID, mine)
		return map[string]any{"conversations": list}, err
	}})
}

// epochOK checks a message against the conversation's key generation. A refusal
// is checked again against the database first, because the answer held for a
// couple of seconds may be from before another node changed it.
func (s *Server) epochOK(o *opCtx, tenant, conv string, st chat.State, epoch int64) (chat.State, error) {
	if !st.Rekey && epoch == st.Epoch {
		return st, nil
	}
	st, err := s.Chat.Fresh(o, tenant, conv)
	if err != nil {
		return st, err
	}
	switch {
	case st.Rekey:
		return st, &apiError{409, "rekey_required", fmt.Sprintf("someone left or a device was revoked: make epoch %d first", st.Epoch+1)}
	case epoch != st.Epoch:
		return st, &apiError{409, "stale_epoch", fmt.Sprintf("the current epoch is %d", st.Epoch)}
	}
	return st, nil
}

func without(list []string, u string) []string {
	out := make([]string, 0, len(list))
	for _, x := range list {
		if x != u {
			out = append(out, x)
		}
	}
	return out
}

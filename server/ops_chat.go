package server

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/oarkflow/rtcd/auth"
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
	// msg.send {conv, id, body}: body is opaque (the client encrypts it). The
	// answer carries the number the message was given; every member, the sender's
	// other devices included, gets msg.new.
	s.register(opDef{name: "msg.send", scope: auth.ScopeChat, relay: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv string `json:"conv"`
			ID   string `json:"id"`
			Body string `json:"body"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		o.note("bytes", len(in.Body)) // the size only; the body is ciphertext
		if err := o.relayAllowed(in.Conv); err != nil {
			return nil, err
		}
		if !s.convLimit.allow(o.sess.who.Tenant+"\x00"+in.Conv, s.cfg.Now()) {
			return nil, &apiError{429, "rate_limited", "this conversation is receiving messages faster than its members can be sent them"}
		}
		m, dup, err := s.Chat.Send(o, o.sess.who.Tenant, in.Conv, o.sess.who.ID, in.ID, in.Body)
		if err != nil {
			return nil, err
		}
		if dup {
			o.note("duplicate", true)
			return map[string]any{"seq": m.Seq, "sent_at": m.Sent, "duplicate": true}, nil
		}
		s.tellConv(o.sess.who.Tenant, ci, "msg.new", m, o.sess.who.ID)
		return map[string]any{"seq": m.Seq, "sent_at": m.Sent}, nil
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
		if err := s.Chat.Delete(o, o.sess.who.Tenant, in.Conv, in.Seq, o.sess.who.ID, ci.admin[o.sess.who.ID]); err != nil {
			return nil, err
		}
		s.tellConv(o.sess.who.Tenant, ci, "msg.deleted", map[string]any{"conv": in.Conv, "seq": in.Seq}, o.sess.who.ID)
		return nil, nil
	})
}

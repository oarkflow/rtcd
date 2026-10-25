package server

import (
	"encoding/json"
	"time"

	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/auth"
)

func (s *Server) registerAdmin() {
	// token.mint is how a backend lets one of its users connect directly.
	s.register(opDef{name: "token.mint", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			User       string   `json:"user"`
			TTLSeconds int      `json:"ttl_seconds"`
			Scopes     []string `json:"scopes"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if !auth.ValidName(in.User) {
			return nil, bad("user is required")
		}
		scopes, err := auth.ParseScopes(in.Scopes)
		if err != nil {
			return nil, bad(err.Error())
		}
		ttl := 15 * time.Minute
		if in.TTLSeconds > 0 {
			ttl = time.Duration(in.TTLSeconds) * time.Second
		}
		if ttl > s.cfg.MaxTokenTTL {
			ttl = s.cfg.MaxTokenTTL
		}
		tok, exp, err := s.auth.Mint(o.sess.who.Tenant, in.User, ttl, scopes)
		if err != nil {
			return nil, bad(err.Error())
		}
		o.target = in.User
		o.note("ttl_seconds", int(ttl.Seconds()))
		o.note("scopes", scopes.Names())
		return map[string]any{"token": tok, "expires_at": exp.UTC().Format(time.RFC3339), "user": in.User, "tenant": o.sess.who.Tenant, "scopes": scopes.Names()}, nil
	}})
	// auth.refresh gives an open connection a new token, so it need not be
	// closed when the old one runs out. The new token must be the same user's.
	s.register(opDef{name: "auth.refresh", quiet: false, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Token string `json:"token"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if o.sess.isService() {
			return nil, bad("a service key does not expire")
		}
		p, err := s.auth.Authenticate(in.Token)
		if err != nil || p.IsService() || p.Tenant != o.sess.who.Tenant || p.User != o.sess.who.ID {
			return nil, unauth("unauthenticated")
		}
		o.sess.scopes.Store(uint32(p.Scopes))
		o.sess.expires.Store(p.Expires.UnixNano())
		return map[string]any{"expires_at": p.Expires.UTC().Format(time.RFC3339)}, nil
	}})
	s.register(opDef{name: "stats", service: true, run: func(o *opCtx, _ json.RawMessage) (any, error) {
		st := s.Stats()
		return map[string]any{
			"rooms": st.Rooms, "peers": st.Peers, "connections": st.Connections,
			"ops_ok": st.OpsOK, "ops_failed": st.OpsFailed, "ops_denied": st.OpsDenied,
			"events_sent": st.EventsSent, "slow_clients_disconnected": st.SlowClientsDisconnected,
			"audit_queued": st.Audit.Queued, "audit_written": st.Audit.Written, "audit_waiting": st.Audit.Waiting,
			"audit_retries": st.Audit.Retries, "audit_refused": st.AuditRefused,
		}, nil
	}})
	// The audit log is readable by the tenant's own services only, and only for
	// that tenant.
	s.register(opDef{name: "audit.query", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Actor, Action, Target, Outcome string
			From, To                       time.Time
			AfterSeq                       uint64 `json:"after_seq"`
			Limit                          int
			Newest                         bool
		}](raw)
		if err != nil {
			return nil, err
		}
		evs, err := s.Audit.Query(o, o.sess.who.Tenant, audit.Filter{Actor: in.Actor, Action: in.Action, Target: in.Target, Outcome: in.Outcome,
			From: in.From, To: in.To, AfterSeq: in.AfterSeq, Limit: in.Limit, Newest: in.Newest})
		if err != nil {
			return nil, err
		}
		if evs == nil {
			evs = []audit.Event{}
		}
		o.note("returned", len(evs))
		return map[string]any{"events": evs}, nil
	}})
	s.register(opDef{name: "audit.verify", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			AfterSeq uint64 `json:"after_seq"`
			Limit    int
		}](raw)
		if err != nil {
			return nil, err
		}
		// Entries still waiting to be stored are part of the log.
		fctx, cancel := contextWithTimeout(o, 5*time.Second)
		defer cancel()
		_ = s.Audit.Flush(fctx)
		v, err := s.Audit.Verify(o, o.sess.who.Tenant, in.AfterSeq, in.Limit)
		if err != nil {
			return nil, err
		}
		seq, hash, _ := s.Audit.Head(o, o.sess.who.Tenant)
		o.note("ok", v.OK)
		return map[string]any{"verification": v, "head_seq": seq, "head_hash": hash}, nil
	}})
}

package server

import (
	"encoding/json"
	"time"

	ws "github.com/oarkflow/fh/pkg/websocket"
	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/auth"
)

// A WebSocket ticket stands in for a token in the connection URL. Browsers
// cannot set headers on a WebSocket, so the credential would otherwise sit in a
// URL that proxies, logs and history keep. A ticket is good for one connection,
// for a few seconds, and means nothing afterwards. It is held in memory on the
// node that issued it, so the connection has to be made to the same node.
const ticketTTL = 30 * time.Second

// closeUser disconnects every connection a user has on this node.
func (h *hubs) closeUser(tenant, user, reason string) int {
	key := userKey(tenant, user)
	sh := h.shardFor(key)
	sh.mu.RLock()
	list := sh.users[key]
	sh.mu.RUnlock()
	for _, c := range list {
		_ = c.ec.Close(ws.ClosePolicyViolation, reason)
	}
	return len(list)
}

func (s *Server) registerSecurity() {
	// ws.ticket: a signed-in caller (a user with a token, or a service acting
	// for a user) trades its credential for a ticket to put in the WebSocket URL.
	s.register(opDef{name: "ws.ticket", run: func(o *opCtx, _ json.RawMessage) (any, error) {
		p := auth.Principal{Tenant: o.sess.who.Tenant, User: o.sess.who.ID, Service: o.sess.service, Scopes: auth.Scopes(o.sess.scopes.Load())}
		if e := o.sess.expires.Load(); e != 0 {
			p.Expires = time.Unix(0, e)
		}
		id, err := s.issueTicket(o, p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ticket": id, "expires_in": int(ticketTTL.Seconds())}, nil
	}})
	// token.revoke: a backend cuts off a user at once (a ban, a stolen token).
	// Tokens already minted stop working and open connections are closed.
	s.register(opDef{name: "token.revoke", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			User string `json:"user"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if !auth.ValidName(in.User) {
			return nil, bad("user is required")
		}
		tenant := o.sess.who.Tenant
		n, err := s.revoke(o, tenant, in.User)
		if err != nil {
			return nil, err
		}
		o.target = in.User
		o.note("connections_closed", n)
		return map[string]any{"revoked": true, "connections_closed": n}, nil
	}})
	_ = audit.OK
}

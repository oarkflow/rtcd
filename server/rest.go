package server

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/auth"
)

// The HTTP interface is for backends that only need a request and a response,
// and for minting the tokens browsers connect with. Every route is one
// operation; the id in the path becomes the "call" or "group" field of the body.

type route struct {
	method, path, op string
	idField          string // "call" or "group": the :id in the path
}

func routes() []route {
	r := []route{
		{"POST", "/v1/tokens", "token.mint", ""},
		{"GET", "/v1/stats", "stats", ""},
		{"POST", "/v1/audit/query", "audit.query", ""},
		{"POST", "/v1/audit/verify", "audit.verify", ""},
		{"POST", "/v1/ice", "ice", ""},
		{"POST", "/v1/ws/ticket", "ws.ticket", ""},
		{"POST", "/v1/tokens/revoke", "token.revoke", ""},
		{"POST", "/v1/calls", "call.start", ""},
		{"GET", "/v1/calls/:id", "call.get", "call"},
		{"POST", "/v1/groups", "group.create", ""},
		{"GET", "/v1/groups", "group.list", ""},
		{"GET", "/v1/groups/:id", "group.get", "group"},
	}
	for _, a := range []string{"open", "admit", "remove", "close", "get"} {
		r = append(r, route{"POST", "/v1/rooms/" + a, "room." + a, ""})
	}
	for _, a := range []string{"open", "admit", "remove", "role", "close", "get", "policy"} {
		r = append(r, route{"POST", "/v1/conversations/" + a, "conv." + a, ""})
	}
	for _, a := range []string{"publish", "revoke", "list"} {
		r = append(r, route{"POST", "/v1/keys/" + a, "key." + a, ""})
	}
	for _, a := range []string{"get", "missing", "rotate", "grant"} {
		r = append(r, route{"POST", "/v1/epochs/" + a, "epoch." + a, ""})
	}
	for _, a := range []string{"answer", "decline", "end", "invite", "signal", "e2ee"} {
		r = append(r, route{"POST", "/v1/calls/:id/" + a, "call." + a, "call"})
	}
	for _, a := range []string{"join", "answer", "candidate", "leave", "ready", "restart", "resync", "prefs", "stats", "sample", "record/start", "record/stop", "record/status"} {
		r = append(r, route{"POST", "/v1/calls/:id/sfu/" + a, "sfu." + strings.ReplaceAll(a, "/", "."), "call"})
	}
	for _, a := range []string{"rename", "add", "remove", "role", "transfer", "delete", "call"} {
		r = append(r, route{"POST", "/v1/groups/:id/" + a, "group." + a, "group"})
	}
	return r
}

func (s *Server) mountREST(app *fh.App) {
	seen := map[string]bool{}
	for _, r := range routes() {
		r := r
		app.Add(r.method, r.path, s.cors(s.rest(r)))
		if !seen[r.path] { // one OPTIONS handler per path, whatever methods it has
			seen[r.path] = true
			app.Options(r.path, s.preflight)
		}
	}
}

func (s *Server) rest(r route) fh.HandlerFunc {
	return func(c fh.Ctx) error {
		ip := strings.Clone(c.IP())
		p, err := s.identify(c, false, ip, "http")
		if err != nil {
			return writeError(c, err)
		}
		if p.IsService() {
			// A service may name the user it acts for; without one it can only
			// use operations that are about the service itself.
			if u := strings.Clone(c.Get("X-RTC-User")); u != "" {
				if p, err = p.WithUser(u); err != nil {
					return writeError(c, bad("X-RTC-User is not a valid user name"))
				}
			}
		}
		// fh reuses its read buffer once the handler returns, and a room outlives
		// the request: everything kept is copied.
		body := append([]byte(nil), c.Body()...)
		if len(body) > s.ops[r.op].bodyLimit() {
			return writeError(c, &apiError{413, "too_large", ""})
		}
		if c.Method() == "POST" && len(body) > 0 && !strings.HasPrefix(strings.ToLower(c.Get("Content-Type")), "application/json") {
			return writeError(c, &apiError{415, "json_required", ""})
		}
		if r.idField != "" {
			if body, err = withField(body, r.idField, strings.Clone(c.Params("id"))); err != nil {
				return writeError(c, err)
			}
		}
		sess := newSession(p, ip, "http", "", s.cfg.Now())
		out, err := s.exec(c.Context(), sess, r.op, body)
		if err != nil {
			return writeError(c, err)
		}
		if out == nil {
			out = map[string]bool{"ok": true}
		}
		return c.Status(200).JSON(out)
	}
}

// withField sets one field of a JSON object body.
func withField(body []byte, field, value string) ([]byte, error) {
	m := map[string]json.RawMessage{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, bad("the body is not a JSON object")
		}
	}
	v, _ := json.Marshal(value)
	m[field] = v
	return json.Marshal(m)
}

func writeError(c fh.Ctx, err error) error {
	status, code, msg := classify(err)
	e := map[string]any{"code": code}
	if msg != "" {
		e["message"] = msg
	}
	return c.Status(status).JSON(map[string]any{"error": e})
}

func (s *Server) cors(next fh.HandlerFunc) fh.HandlerFunc {
	return func(c fh.Ctx) error {
		if o := c.Get("Origin"); o != "" && s.originAllowed(o) {
			c.Set("Access-Control-Allow-Origin", strings.Clone(o))
			c.Set("Vary", "Origin")
		}
		return next(c)
	}
}

func (s *Server) preflight(c fh.Ctx) error {
	o := c.Get("Origin")
	if o == "" || !s.originAllowed(o) {
		return c.SendStatus(403)
	}
	c.Set("Access-Control-Allow-Origin", strings.Clone(o))
	c.Set("Vary", "Origin")
	c.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	c.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-RTC-User")
	c.Set("Access-Control-Max-Age", "600")
	return c.SendStatus(204)
}

// transportIsSecure reports whether the request arrived over TLS or from the
// same machine.
func transportIsSecure(c fh.Ctx) bool {
	if c.Protocol() == "https" || strings.EqualFold(c.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	ip := net.ParseIP(c.IP())
	return ip != nil && ip.IsLoopback()
}

// identify resolves the caller. Browsers cannot set headers on a WebSocket, so
// the WebSocket alone may carry the token in the query string. Failures are
// audited, within a budget so they cannot be used to fill the log.
func (s *Server) identify(c fh.Ctx, queryToken bool, ip, transport string) (auth.Principal, error) {
	if !s.cfg.InsecureHTTP && !transportIsSecure(c) {
		s.auditAnon("auth.rejected", "tls_required", ip, transport)
		return auth.Principal{}, &apiError{426, "tls_required", ""}
	}
	now := s.cfg.Now()
	cred := auth.Bearer(c.Get("Authorization"))
	if cred == "" && queryToken {
		if t := strings.Clone(c.Query("ticket")); t != "" {
			if p, ok := s.redeemTicket(c.Context(), t); ok && !(!p.Expires.IsZero() && !now.Before(p.Expires)) {
				return p, nil
			}
			if s.authFail.exhausted(ip, now) {
				return auth.Principal{}, &apiError{429, "rate_limited", "too many failed sign-ins from this address"}
			}
			s.authFail.allow(ip, now)
			s.auditAnon("auth.failed", "unauthenticated", ip, transport)
			return auth.Principal{}, unauth("unauthenticated")
		}
		cred = strings.Clone(c.Query("token"))
	}
	p, err := s.auth.Authenticate(cred)
	if err != nil {
		// An address that keeps presenting bad credentials is told so, and its
		// failures stop being logged one by one. A good credential is never held
		// back by this: people behind a shared address are not locked out by
		// someone else's mistakes (the keys are long enough that guessing is not
		// what this protects against; the log and the CPU are).
		if s.authFail.exhausted(ip, now) {
			s.auditAnon("auth.throttled", "rate_limited", ip, transport)
			return auth.Principal{}, &apiError{429, "rate_limited", "too many failed sign-ins from this address"}
		}
		s.authFail.allow(ip, now)
		s.auditAnon("auth.failed", "unauthenticated", ip, transport)
		return auth.Principal{}, unauth("unauthenticated")
	}
	p.Tenant, p.Service, p.User = strings.Clone(p.Tenant), strings.Clone(p.Service), strings.Clone(p.User)
	return p, nil
}

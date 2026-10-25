package server

import (
	"context"
	"encoding/json"

	"github.com/oarkflow/rtcd/auth"
)

// ExecForBenchmark runs one operation as a signed-in user, with no transport.
func (s *Server) ExecForBenchmark(user, tenant, op string, in json.RawMessage) error {
	sess := newSession(auth.Principal{Tenant: tenant, User: user, Scopes: auth.UserScopes}, "127.0.0.1", "ws", "bench", s.cfg.Now())
	_, err := s.exec(context.Background(), sess, op, in)
	return err
}

// DeliverForBenchmark pushes an event to a user.
func (s *Server) DeliverForBenchmark(tenant, user string, data json.RawMessage) error {
	return s.hubs.deliver(tenant, user, "bench", data, "x")
}

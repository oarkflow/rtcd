package server

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/calls"
)

func validUsers(users []string) error {
	for _, u := range users {
		if !auth.ValidName(u) {
			return bad("a user name is not valid")
		}
	}
	return nil
}

func (s *Server) registerOps() {
	s.registerAdmin()
	s.registerCalls()
	s.registerRooms()
	s.registerSFU()
	s.registerGroups()
}

type callRef struct {
	Call string `json:"call"`
}

func (s *Server) registerCalls() {
	s.register(opDef{name: "ice", scope: auth.ScopeCalls, quiet: true, run: func(o *opCtx, _ json.RawMessage) (any, error) {
		return map[string]any{"ice": s.Store.ICE(o.sess.who.ID)}, nil
	}})
	s.register(opDef{name: "call.start", scope: auth.ScopeCalls, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			To   []string `json:"to"`
			Kind string   `json:"kind"`
			Mode string   `json:"mode"`
			E2EE *bool    `json:"e2ee"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if err := validUsers(in.To); err != nil {
			return nil, err
		}
		if in.Kind == "" {
			in.Kind = "video"
		}
		if in.Mode == "" {
			in.Mode = calls.P2P
		}
		o.note("mode", in.Mode)
		o.note("kind", in.Kind)
		o.note("invitees", in.To)
		c, err := s.Store.StartCall(o, o.actor(), in.To, in.Kind, in.Mode, in.E2EE)
		if err != nil {
			return nil, err
		}
		o.target = c.ID
		o.note("e2ee", c.E2EE)
		return map[string]any{"call": c, "ice": s.Store.ICE(o.sess.who.ID)}, nil
	}})
	s.register(opDef{name: "call.get", scope: auth.ScopeCalls, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[callRef](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Call
		return s.Store.Get(o, o.actor(), in.Call)
	}})
	s.register(opDef{name: "call.answer", scope: auth.ScopeCalls, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[callRef](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Call
		c, err := s.Store.Answer(o, o.actor(), in.Call)
		if err != nil {
			return nil, err
		}
		return map[string]any{"call": c, "ice": s.Store.ICE(o.sess.who.ID)}, nil
	}})
	s.register(opDef{name: "call.decline", scope: auth.ScopeCalls, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[callRef](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Call
		c, err := s.Store.Decline(o, o.actor(), in.Call)
		if err == nil {
			s.left(c, o.sess.who.ID)
		}
		return c, err
	}})
	s.register(opDef{name: "call.end", scope: auth.ScopeCalls, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[callRef](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Call
		c, err := s.Store.End(o, o.actor(), in.Call)
		if err == nil {
			s.left(c, o.sess.who.ID)
			o.note("reason", c.Reason)
		}
		return c, err
	}})
	s.register(opDef{name: "call.invite", scope: auth.ScopeCalls, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Call  string   `json:"call"`
			Users []string `json:"users"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if err := validUsers(in.Users); err != nil {
			return nil, err
		}
		o.target = in.Call
		o.note("users", in.Users)
		return s.Store.Invite(o, o.actor(), in.Call, in.Users)
	}})
	// signal and e2ee are relays: they carry a message from one person in a call
	// to another and read only memory.
	s.register(opDef{name: "call.signal", scope: auth.ScopeCalls, relay: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Call string          `json:"call"`
			To   string          `json:"to"`
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if !auth.ValidName(in.To) || in.Type == "" {
			return nil, bad("to and type are required")
		}
		o.target = in.Call
		o.note("to", in.To)
		o.note("type", in.Type)
		o.note("bytes", len(in.Data))
		if err := o.relayAllowed(in.Call); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, s.Store.Signal(o, o.actor(), in.Call, in.To, in.Type, in.Data)
	}})
	s.register(opDef{name: "call.e2ee", scope: auth.ScopeCalls, relay: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Call string `json:"call"`
			To   string `json:"to"`
			Data string `json:"data"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if !auth.ValidName(in.To) {
			return nil, bad("to is required")
		}
		o.target = in.Call
		o.note("to", in.To)
		o.note("bytes", len(in.Data)) // the size only: the contents are ciphertext the service cannot read anyway
		if err := o.relayAllowed(in.Call); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, s.Store.Relay(o, o.actor(), in.Call, in.To, in.Data)
	}})
}

// Notify implements calls.Notifier and groups.Notifier.
func (s *Server) Notify(_ context.Context, tenant, user, event string, data json.RawMessage, from string) error {
	if strings.HasPrefix(event, "group.") || strings.HasPrefix(event, "conv.") {
		s.dropConvs() // membership may have changed: the next message checks again
	}
	s.publish(tenant, user, event, data, from)
	return s.hubs.deliver(tenant, user, event, data, from)
}

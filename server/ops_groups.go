package server

import (
	"encoding/json"
	"hash/fnv"

	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/calls"
	"github.com/oarkflow/rtcd/groups"
)

type groupRef struct {
	Group string `json:"group"`
}

func (s *Server) gactor(o *opCtx) groups.Actor { return groups.Actor(o.sess.who) }

func (s *Server) registerGroups() {
	g := func(name string, run func(o *opCtx, raw json.RawMessage) (any, error)) {
		s.register(opDef{name: "group." + name, scope: auth.ScopeGroups, run: run})
	}
	g("create", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Name    string   `json:"name"`
			Members []string `json:"members"`
		}](raw)
		if err != nil {
			return nil, err
		}
		gr, err := s.Groups.Create(o, s.gactor(o), in.Name, in.Members)
		if err == nil {
			o.target = gr.ID
			o.note("name", gr.Name)
			o.note("members", len(gr.Members))
		}
		return gr, err
	})
	g("get", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[groupRef](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		return s.Groups.Get(o, s.gactor(o), in.Group)
	})
	g("list", func(o *opCtx, _ json.RawMessage) (any, error) {
		l, err := s.Groups.List(o, s.gactor(o))
		if l == nil {
			l = []groups.Group{}
		}
		o.note("count", len(l))
		return map[string]any{"groups": l}, err
	})
	g("rename", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Group string `json:"group"`
			Name  string `json:"name"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		o.note("name", in.Name)
		return s.Groups.Rename(o, s.gactor(o), in.Group, in.Name)
	})
	g("add", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Group string   `json:"group"`
			Users []string `json:"users"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		o.note("users", in.Users)
		return s.Groups.Add(o, s.gactor(o), in.Group, in.Users)
	})
	g("remove", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Group string   `json:"group"`
			Users []string `json:"users"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		o.note("users", in.Users)
		return s.Groups.Remove(o, s.gactor(o), in.Group, in.Users)
	})
	g("role", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Group string `json:"group"`
			User  string `json:"user"`
			Role  string `json:"role"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		o.note("user", in.User)
		o.note("role", in.Role)
		return s.Groups.SetRole(o, s.gactor(o), in.Group, in.User, in.Role)
	})
	g("transfer", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Group string `json:"group"`
			To    string `json:"to"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		o.note("to", in.To)
		return s.Groups.Transfer(o, s.gactor(o), in.Group, in.To)
	})
	g("delete", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[groupRef](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		return map[string]any{"ok": true}, s.Groups.Delete(o, s.gactor(o), in.Group)
	})
	// group.call starts a call with the group, or, if the group already has one
	// under way, rings the caller into it. Members of the group are rung.
	s.register(opDef{name: "group.call", scope: auth.ScopeGroups | auth.ScopeCalls, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Group string `json:"group"`
			Kind  string `json:"kind"`
			Mode  string `json:"mode"`
			E2EE  *bool  `json:"e2ee"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Group
		members, err := s.Groups.Members(o, s.gactor(o), in.Group) // also checks the caller belongs
		if err != nil {
			return nil, err
		}
		// Two members calling at the same moment must end up in one call.
		h := fnv.New32a()
		_, _ = h.Write([]byte(o.sess.who.Tenant + "\x00" + in.Group))
		mu := &s.glocks[h.Sum32()%uint32(len(s.glocks))]
		mu.Lock()
		defer mu.Unlock()
		if c, ok, err := s.Store.ActiveGroupCall(o, o.sess.who.Tenant, in.Group); err != nil {
			return nil, err
		} else if ok {
			c, err = s.Store.JoinGroupCall(o, o.actor(), c.ID)
			if err != nil {
				return nil, err
			}
			o.note("call", c.ID)
			o.note("joined_existing", true)
			return map[string]any{"call": c, "ice": s.Store.ICE(o.sess.who.ID), "joined_existing": true}, nil
		}
		if in.Kind == "" {
			in.Kind = "video"
		}
		if in.Mode == "" {
			in.Mode = calls.SFU
		}
		var to []string
		for _, m := range members {
			if m != o.sess.who.ID {
				to = append(to, m)
			}
		}
		c, err := s.Store.StartWith(o, o.actor(), calls.StartOptions{To: to, Kind: in.Kind, Mode: in.Mode, E2EE: in.E2EE, Group: in.Group})
		if err != nil {
			return nil, err
		}
		o.note("call", c.ID)
		o.note("invitees", len(to))
		return map[string]any{"call": c, "ice": s.Store.ICE(o.sess.who.ID)}, nil
	}})
}

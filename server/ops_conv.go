package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/oarkflow/rtcd/chat"
	"github.com/oarkflow/rtcd/groups"
)

// Managed conversations (service key only) are how a backend that owns its own
// membership uses chat. It opens a conversation under its own id and keeps the
// member list in step with its own; users reach it with tokens it minted. A
// removal takes effect at once, and the conversation then requires a new key
// epoch. See groups.OpenManaged.

type convBody struct {
	ID      string   `json:"id"`
	Members []string `json:"members"`
	Admins  []string `json:"admins"`
	User    string   `json:"user"`
	Role    string   `json:"role"`
	// Policy, in seconds; absent fields are left as they are.
	Retention    *int64 `json:"retention"`
	DefaultTTL   *int64 `json:"default_ttl"`
	DeleteWindow *int64 `json:"delete_window"`
}

func (b convBody) policy() (chat.Policy, bool) {
	var p chat.Policy
	d := func(v *int64) *time.Duration {
		if v == nil {
			return nil
		}
		x := time.Duration(*v) * time.Second
		return &x
	}
	p.Retention, p.TTL, p.DeleteWindow = d(b.Retention), d(b.DefaultTTL), d(b.DeleteWindow)
	return p, p.Retention != nil || p.TTL != nil || p.DeleteWindow != nil
}

func (s *Server) registerConvs() {
	reg := func(name string, run func(o *opCtx, in convBody) (any, error)) {
		s.register(opDef{name: "conv." + name, service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
			in, err := decode[convBody](raw)
			if err != nil {
				return nil, err
			}
			o.target = in.ID
			return run(o, in)
		}})
	}
	tell := func(tenant string, users []string, event string, v any) {
		raw, _ := jsonMarshal(v)
		for _, u := range users {
			_ = s.Notify(context.Background(), tenant, u, event, raw, "")
		}
	}
	state := func(o *opCtx, in convBody) (chat.State, error) {
		return s.Chat.Fresh(o, o.sess.who.Tenant, in.ID)
	}

	// conv.open {id, members, admins, retention, default_ttl, delete_window}:
	// creates the conversation, or admits the people if it exists.
	reg("open", func(o *opCtx, in convBody) (any, error) {
		if err := validUsers(in.Members); err != nil {
			return nil, err
		}
		if err := validUsers(in.Admins); err != nil {
			return nil, err
		}
		tenant := o.sess.who.Tenant
		p, setPolicy := in.policy()
		added, created, err := s.Groups.OpenManaged(o, tenant, in.ID, in.Members, in.Admins)
		if err != nil {
			return nil, err
		}
		o.note("members", len(added))
		if setPolicy {
			if err := s.Chat.SetPolicy(o, tenant, in.ID, p); err != nil {
				return nil, err
			}
		}
		s.dropConvs()
		s.announceAdded(o, tenant, in.ID, added)
		st, err := state(o, in)
		return map[string]any{"conv": in.ID, "created": created, "added": added, "state": st}, err
	})
	// conv.admit {id, members, admins}: lets people in (admins become administrators).
	reg("admit", func(o *opCtx, in convBody) (any, error) {
		if err := validUsers(in.Members); err != nil {
			return nil, err
		}
		if err := validUsers(in.Admins); err != nil {
			return nil, err
		}
		tenant := o.sess.who.Tenant
		added, err := s.Groups.AdmitManaged(o, tenant, in.ID, in.Members, in.Admins)
		if err != nil {
			return nil, err
		}
		o.note("members", len(added))
		s.dropConvs()
		s.announceAdded(o, tenant, in.ID, added)
		return map[string]any{"conv": in.ID, "added": added}, nil
	})
	// conv.remove {id, members}: takes people out at once. The conversation then
	// requires a new key epoch and the people removed lose their wrapped keys.
	reg("remove", func(o *opCtx, in convBody) (any, error) {
		if err := validUsers(in.Members); err != nil {
			return nil, err
		}
		tenant := o.sess.who.Tenant
		gone, err := s.Groups.RemoveManaged(o, tenant, in.ID, in.Members)
		if err != nil {
			return nil, err
		}
		o.note("members", len(gone))
		s.dropConvs()
		if len(gone) > 0 {
			tell(tenant, gone, "conv.removed", map[string]any{"conv": in.ID})
			if list, err := s.Groups.Roster(o, tenant, in.ID); err == nil {
				left := make([]string, len(list))
				for i, m := range list {
					left[i] = m.User
				}
				tell(tenant, left, "conv.members", map[string]any{"conv": in.ID, "removed": gone})
			}
		}
		st, err := state(o, in)
		return map[string]any{"conv": in.ID, "removed": gone, "state": st}, err
	})
	// conv.role {id, user, role}: admin or member.
	reg("role", func(o *opCtx, in convBody) (any, error) {
		if err := s.Groups.SetManagedRole(o, o.sess.who.Tenant, in.ID, in.User, in.Role); err != nil {
			return nil, err
		}
		s.dropConvs()
		return nil, nil
	})
	// conv.close {id}: deletes the conversation with its messages, keys and files.
	reg("close", func(o *opCtx, in convBody) (any, error) {
		tenant := o.sess.who.Tenant
		members, err := s.Groups.CloseManaged(o, tenant, in.ID)
		if err != nil {
			return nil, err
		}
		o.note("members", len(members))
		tell(tenant, members, "conv.closed", map[string]any{"conv": in.ID})
		return map[string]any{"conv": in.ID}, nil
	})
	// conv.get {id}: who is in a conversation (managed or not) and its key state.
	reg("get", func(o *opCtx, in convBody) (any, error) {
		tenant := o.sess.who.Tenant
		list, err := s.Groups.Roster(o, tenant, in.ID)
		if err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, groups.ErrForbidden
		}
		st, err := state(o, in)
		return map[string]any{"conv": in.ID, "members": list, "state": st}, err
	})
	// conv.policy {id, retention, default_ttl, delete_window}: seconds.
	reg("policy", func(o *opCtx, in convBody) (any, error) {
		tenant := o.sess.who.Tenant
		list, err := s.Groups.Roster(o, tenant, in.ID)
		if err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, groups.ErrForbidden
		}
		p, ok := in.policy()
		if !ok {
			return nil, bad("name at least one of retention, default_ttl, delete_window")
		}
		if err := s.Chat.SetPolicy(o, tenant, in.ID, p); err != nil {
			return nil, err
		}
		st, err := state(o, in)
		return map[string]any{"conv": in.ID, "state": st}, err
	})
}

// announceAdded tells new members they are in, and the others who joined, and
// asks every member's client to grant the new devices the current key.
func (s *Server) announceAdded(ctx context.Context, tenant, id string, added []string) {
	if len(added) == 0 {
		return
	}
	list, err := s.Groups.Roster(ctx, tenant, id)
	if err != nil {
		return
	}
	isNew := map[string]bool{}
	for _, u := range added {
		isNew[u] = true
	}
	newRaw, _ := jsonMarshal(map[string]any{"conv": id})
	oldRaw, _ := jsonMarshal(map[string]any{"conv": id, "added": added})
	for _, m := range list {
		if isNew[m.User] {
			_ = s.Notify(ctx, tenant, m.User, "conv.added", newRaw, "")
		} else {
			_ = s.Notify(ctx, tenant, m.User, "conv.members", oldRaw, "")
		}
	}
}

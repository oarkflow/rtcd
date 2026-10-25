package calls

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Managed rooms.
//
// A backend that already knows who may be in a call (its own membership, its
// own ringing, its own permissions) opens a room here instead of placing a
// call. There is no ringing and no invitation: everyone the backend admits is
// "joined" at once, and may connect to the SFU. The cap on invitees does not
// apply (a room may hold MaxRoomMembers people), and nobody but the backend can
// end the room for everyone. Who is in the room is the backend's decision and
// is changed with Admit and Remove.

// managedInitiator is the "initiator" of a managed room. No user can have this
// name (auth.ValidName rejects control characters), so no user is ever the one
// who may end the room for everyone.
const managedInitiator = "\x1fmanaged"

// DefaultMaxRoomMembers bounds a managed room when Options.MaxRoomMembers is 0.
const DefaultMaxRoomMembers = 1000

// RoomOptions describes a managed room.
type RoomOptions struct {
	// ID is the backend's own identifier for the call. It must be unique across
	// tenants; use something unguessable.
	ID      string
	Kind    string // audio or video
	E2EE    *bool  // nil takes the store's policy
	Members []string
}

func validRoomID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// Managed reports whether the call is a managed room.
func (c Call) Managed() bool { return c.Initiator == managedInitiator }

// OpenRoom creates a managed room, or, if the tenant already has a live one
// with this id, admits the members to it. It never rings anybody.
func (s *Store) OpenRoom(ctx context.Context, tenant string, o RoomOptions) (Call, error) {
	if tenant == "" || !validRoomID(o.ID) {
		return Call{}, fmt.Errorf("%w: a room id is 1 to 128 letters, digits, '-', '_' or '.'", ErrInvalid)
	}
	kind := o.Kind
	if kind == "" {
		kind = "video"
	}
	if kind != "audio" && kind != "video" {
		return Call{}, fmt.Errorf("%w: kind must be audio or video", ErrInvalid)
	}
	secure := s.o.RequireE2EE
	if o.E2EE != nil {
		if !*o.E2EE && s.o.RequireE2EE {
			return Call{}, fmt.Errorf("%w: this server only allows end-to-end encrypted calls", ErrInvalid)
		}
		secure = *o.E2EE
	}
	members := dedupe(o.Members)
	if len(members) > s.maxRoom() {
		return Call{}, fmt.Errorf("%w: at most %d people can be in a room", ErrInvalid, s.maxRoom())
	}
	if existing, err := s.fresh(ctx, o.ID); err == nil {
		if existing.Tenant != tenant || !existing.Managed() {
			return Call{}, ErrForbidden // never reveal that the id belongs to someone else
		}
		if existing.Status == Ended {
			return Call{}, ErrState
		}
		return s.Admit(ctx, tenant, o.ID, members)
	} else if !errors.Is(err, ErrNotFound) {
		return Call{}, err
	}
	now := s.o.Now()
	secureBit := 0
	if secure {
		secureBit = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Call{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_calls (id, kind, mode, initiator, tenant, status, created_at, answered_at, e2ee, group_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`),
		o.ID, kind, SFU, managedInitiator, tenant, Active, ts(now), ts(now), secureBit, ""); err != nil {
		return Call{}, ErrForbidden // lost a race for the id
	}
	for _, u := range members {
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_participants (call_id, user_id, state) VALUES ($1,$2,$3)`), o.ID, u, "joined"); err != nil {
			return Call{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Call{}, err
	}
	return s.fresh(ctx, o.ID)
}

func (s *Store) maxRoom() int {
	if s.o.MaxRoomMembers > 0 {
		return s.o.MaxRoomMembers
	}
	return DefaultMaxRoomMembers
}

func dedupe(users []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(users))
	for _, u := range users {
		if u = strings.TrimSpace(u); u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func (s *Store) managed(ctx context.Context, tenant, id string) (Call, error) {
	c, err := s.load(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Call{}, ErrForbidden
		}
		return Call{}, err
	}
	if c.Tenant != tenant || !c.Managed() {
		return Call{}, ErrForbidden
	}
	return c, nil
}

// Admit lets users into a managed room. People who were removed are let back.
func (s *Store) Admit(ctx context.Context, tenant, id string, users []string) (Call, error) {
	c, err := s.managed(ctx, tenant, id)
	if err != nil {
		return Call{}, err
	}
	if c.Status == Ended {
		return Call{}, ErrState
	}
	users = dedupe(users)
	var add []string
	for _, u := range users {
		if st, ok := c.role(u); !ok || st != "joined" {
			add = append(add, u)
		}
	}
	if len(add) == 0 {
		return c, nil
	}
	known := map[string]bool{}
	for _, p := range c.Participants {
		known[p.User] = true
	}
	total := len(c.Participants)
	for _, u := range add {
		if !known[u] {
			total++
		}
	}
	if total > s.maxRoom() {
		return Call{}, fmt.Errorf("%w: at most %d people can be in a room", ErrInvalid, s.maxRoom())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Call{}, err
	}
	defer tx.Rollback()
	for _, u := range add {
		if known[u] {
			_, err = tx.ExecContext(ctx, s.rebind(`UPDATE rtc_participants SET state = $1 WHERE call_id = $2 AND user_id = $3`), "joined", id, u)
		} else {
			_, err = tx.ExecContext(ctx, s.rebind(s.ignore+` rtc_participants (call_id, user_id, state) VALUES ($1,$2,$3)`+s.suffix), id, u, "joined")
		}
		if err != nil {
			return Call{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Call{}, err
	}
	s.cache.drop(id)
	return s.fresh(ctx, id)
}

// Remove takes users out of a managed room. They keep a row, as "left", so the
// room's history is whole, but they may no longer use the SFU.
func (s *Store) Remove(ctx context.Context, tenant, id string, users []string) (Call, error) {
	c, err := s.managed(ctx, tenant, id)
	if err != nil {
		return Call{}, err
	}
	if c.Status == Ended {
		return c, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Call{}, err
	}
	defer tx.Rollback()
	for _, u := range dedupe(users) {
		if st, ok := c.role(u); ok && st != "left" {
			if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE rtc_participants SET state = $1 WHERE call_id = $2 AND user_id = $3`), "left", id, u); err != nil {
				return Call{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return Call{}, err
	}
	s.cache.drop(id)
	return s.fresh(ctx, id)
}

// CloseRoom ends a managed room for everyone.
func (s *Store) CloseRoom(ctx context.Context, tenant, id, reason string) (Call, error) {
	c, err := s.managed(ctx, tenant, id)
	if err != nil {
		return Call{}, err
	}
	if reason == "" {
		reason = "ended"
	}
	return s.finish(ctx, c, reason, "")
}

// Roster lists the users admitted to a managed room.
func (c Call) Roster() []string {
	out := make([]string, 0, len(c.Participants))
	for _, p := range c.Participants {
		if p.State == "joined" {
			out = append(out, p.User)
		}
	}
	return out
}

// RoomView returns a managed room of the tenant.
func (s *Store) RoomView(ctx context.Context, tenant, id string) (Call, error) {
	return s.managed(ctx, tenant, id)
}

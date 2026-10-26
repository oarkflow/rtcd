package groups

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Managed conversations are for a backend that already knows who belongs in a
// conversation (it has its own contacts, groups and permissions). The backend,
// holding a service key, opens a conversation under its own id and says who is
// in it and who administers it. They are groups underneath, so messages, files
// and keys work the same, but they have no owner and no user can see, rename,
// add to or delete one: to the group.* operations they do not exist.

// ErrIDTaken means the id belongs to a conversation of another tenant, or to a
// group a user made. The two are not told apart.
var ErrIDTaken = errors.New("groups: id taken")

// ManagedOwner is the owner recorded for a managed conversation.
const ManagedOwner = "~"

func (s *Store) managedID(id string) error {
	if id == "" || len(id) > 128 || strings.HasPrefix(id, "grp_") || !s.o.ValidUser(id) {
		return fmt.Errorf("%w: a conversation id is 1 to 128 characters and does not start with grp_", ErrInvalid)
	}
	return nil
}

func (s *Store) isManaged(ctx context.Context, tenant, id string) (managed, exists bool, err error) {
	var t string
	err = s.db.QueryRowContext(ctx, s.rebind(`SELECT tenant FROM rtc_groups WHERE id=$1`), id).Scan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if t != tenant {
		return false, true, ErrIDTaken
	}
	var n int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_managed WHERE id=$1`), id).Scan(&n); err != nil {
		return false, true, err
	}
	return n > 0, true, nil
}

// OpenManaged creates a managed conversation, or admits the people to it if it
// is already open. It reports who was added.
func (s *Store) OpenManaged(ctx context.Context, tenant, id string, members, admins []string) (added []string, created bool, err error) {
	if err := s.managedID(id); err != nil {
		return nil, false, err
	}
	managed, exists, err := s.isManaged(ctx, tenant, id)
	if err != nil {
		return nil, false, err
	}
	if exists && !managed {
		return nil, false, ErrIDTaken
	}
	if !exists {
		now := s.o.Now().Format(tsLayout)
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, false, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_groups (id, tenant, name, owner, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)`), id, tenant, id, ManagedOwner, now, now); err != nil {
			if isDup(err) {
				return nil, false, ErrIDTaken // lost a race to another tenant opening the same id
			}
			return nil, false, err
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_managed (id, tenant) VALUES ($1,$2)`), id, tenant); err != nil {
			return nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		created = true
	}
	added, err = s.AdmitManaged(ctx, tenant, id, members, admins)
	return added, created, err
}

// AdmitManaged adds people to a managed conversation, and makes the named admins
// administrators (an existing member can be promoted this way). It reports who
// was added.
func (s *Store) AdmitManaged(ctx context.Context, tenant, id string, members, admins []string) ([]string, error) {
	all, err := s.users(append(append([]string{}, members...), admins...))
	if err != nil {
		return nil, err
	}
	adm, err := s.users(admins)
	if err != nil {
		return nil, err
	}
	managed, exists, err := s.isManaged(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	if !exists || !managed {
		return nil, ErrForbidden
	}
	var n int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_group_members WHERE group_id=$1`), id).Scan(&n); err != nil {
		return nil, err
	}
	have := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT user_id FROM rtc_group_members WHERE group_id=$1`), id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return nil, err
		}
		have[u] = true
	}
	rows.Close()
	now := s.o.Now().Format(tsLayout)
	var added []string
	for _, u := range all {
		if have[u] {
			continue
		}
		if n+len(added)+1 > s.o.MaxManaged {
			return added, fmt.Errorf("%w: a conversation holds at most %d people", ErrLimit, s.o.MaxManaged)
		}
		role := RoleMember
		if contains(adm, u) {
			role = RoleAdmin
		}
		if _, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_group_members (group_id, user_id, role, added_at) VALUES ($1,$2,$3,$4)`), id, u, role, now); err != nil {
			if isDup(err) {
				continue
			}
			return added, err
		}
		added = append(added, u)
	}
	for _, u := range adm {
		if have[u] {
			if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_group_members SET role=$1 WHERE group_id=$2 AND user_id=$3`), RoleAdmin, id, u); err != nil {
				return added, err
			}
		}
	}
	_, _ = s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_groups SET updated_at=$1 WHERE id=$2`), now, id)
	return added, nil
}

// SetManagedRole makes a member an admin or an ordinary member.
func (s *Store) SetManagedRole(ctx context.Context, tenant, id, user, role string) error {
	if role != RoleAdmin && role != RoleMember {
		return fmt.Errorf("%w: a role is admin or member", ErrInvalid)
	}
	managed, exists, err := s.isManaged(ctx, tenant, id)
	if err != nil {
		return err
	}
	if !exists || !managed {
		return ErrForbidden
	}
	r, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_group_members SET role=$1 WHERE group_id=$2 AND user_id=$3`), role, id, user)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %q is not in the conversation", ErrInvalid, user)
	}
	return nil
}

// RemoveManaged takes people out of a managed conversation, and reports who was in it.
func (s *Store) RemoveManaged(ctx context.Context, tenant, id string, users []string) ([]string, error) {
	list, err := s.users(users)
	if err != nil {
		return nil, err
	}
	managed, exists, err := s.isManaged(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	if !exists || !managed {
		return nil, ErrForbidden
	}
	var gone []string
	for _, u := range list {
		r, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_group_members WHERE group_id=$1 AND user_id=$2`), id, u)
		if err != nil {
			return gone, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			gone = append(gone, u)
		}
	}
	if len(gone) > 0 {
		_, _ = s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_groups SET updated_at=$1 WHERE id=$2`), s.o.Now().Format(tsLayout), id)
		if s.o.OnRemove != nil {
			s.o.OnRemove(ctx, tenant, id, gone)
		}
	}
	return gone, nil
}

// CloseManaged deletes a managed conversation and reports who was in it.
func (s *Store) CloseManaged(ctx context.Context, tenant, id string) ([]string, error) {
	managed, exists, err := s.isManaged(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	if !exists || !managed {
		return nil, ErrForbidden
	}
	ms, err := s.members(ctx, id)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM rtc_group_members WHERE group_id=$1`, `DELETE FROM rtc_managed WHERE id=$1`, `DELETE FROM rtc_groups WHERE id=$1`} {
		if _, err := tx.ExecContext(ctx, s.rebind(q), id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if s.o.OnDelete != nil {
		s.o.OnDelete(ctx, tenant, id)
	}
	return userNames(ms), nil
}

// ConvsOf returns the ids of the groups and managed conversations a user is in
// (at most 1000).
func (s *Store) ConvsOf(ctx context.Context, tenant, user string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT g.id FROM rtc_groups g JOIN rtc_group_members m ON m.group_id = g.id WHERE g.tenant = $1 AND m.user_id = $2 LIMIT 1000`), tenant, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func isDup(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "unique constraint") || strings.Contains(m, "duplicate key") || strings.Contains(m, "duplicate entry") || strings.Contains(m, "23505") || strings.Contains(m, "1062")
}

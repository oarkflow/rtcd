// Package groups lets users make groups of their own and manage who is in them.
//
// A group belongs to one tenant. Its creator is its owner; the owner can make
// others admins, and owners and admins add and remove members. Only members can
// see a group: to everyone else a group that exists and one that does not look
// the same.
package groups

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oarkflow/rtcd/dbx"
	"strings"
	"time"
	"unicode/utf8"
)

// Errors.
var (
	ErrForbidden = errors.New("groups: not allowed")
	ErrInvalid   = errors.New("groups: invalid request")
	ErrLimit     = errors.New("groups: limit reached")
)

// Roles.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Actor is the acting user.
type Actor struct{ ID, Tenant string }

// Notifier delivers an event to one user. It must not block.
type Notifier interface {
	Notify(ctx context.Context, tenant, user, event string, data json.RawMessage, from string) error
}

// Member is one person in a group.
type Member struct {
	User    string    `json:"user"`
	Role    string    `json:"role"`
	AddedAt time.Time `json:"added_at"`
}

// Group is a group and its members.
type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Members   []Member  `json:"members,omitempty"`
}

// Options configure a Store.
type Options struct {
	Dialect  string
	Rebind   func(string) string
	Notifier Notifier
	// ValidUser says whether a string may be a user name. Default: non-empty,
	// at most 128 characters, no control characters.
	ValidUser func(string) bool
	// MaxOwned caps the groups one user may own. Default 100.
	MaxOwned int
	// MaxMembers caps the people in one group. Default 200.
	MaxMembers int
	Now        func() time.Time
	// MaxManaged caps the people in one managed conversation. Default 1000.
	MaxManaged int
	// OnRemove is called once after people leave or are removed from a group or
	// managed conversation; OnDelete after one is deleted. They run on the
	// caller's goroutine and must not block.
	OnRemove func(ctx context.Context, tenant, id string, users []string)
	OnDelete func(ctx context.Context, tenant, id string)
}

// Store keeps groups in SQL.
type Store struct {
	db     *sql.DB
	o      Options
	rebind func(string) string
}

// Open prepares the schema.
func Open(ctx context.Context, db *sql.DB, o Options) (*Store, error) {
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.MaxOwned <= 0 {
		o.MaxOwned = 100
	}
	if o.MaxMembers <= 0 {
		o.MaxMembers = 200
	}
	if o.MaxManaged <= 0 {
		o.MaxManaged = 1000
	}
	if o.ValidUser == nil {
		o.ValidUser = func(s string) bool {
			if s == "" || len(s) > 128 || !utf8.ValidString(s) || s != strings.TrimSpace(s) {
				return false
			}
			for _, r := range s {
				if r < 0x20 || r == 0x7f {
					return false
				}
			}
			return true
		}
	}
	s := &Store{db: db, o: o, rebind: o.Rebind}
	if s.rebind == nil {
		s.rebind = func(q string) string { return q }
	}
	key := "VARCHAR(191)"
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS rtc_groups (id ` + key + ` PRIMARY KEY, tenant ` + key + ` NOT NULL, name ` + key + ` NOT NULL,
			owner ` + key + ` NOT NULL, created_at ` + key + ` NOT NULL, updated_at ` + key + ` NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS rtc_group_members (group_id ` + key + ` NOT NULL, user_id ` + key + ` NOT NULL,
			role VARCHAR(16) NOT NULL, added_at ` + key + ` NOT NULL, PRIMARY KEY (group_id, user_id))`,
		`CREATE INDEX IF NOT EXISTS rtc_group_members_user ON rtc_group_members (user_id)`,
		`CREATE INDEX IF NOT EXISTS rtc_groups_owner ON rtc_groups (tenant, owner)`,
		`CREATE TABLE IF NOT EXISTS rtc_managed (id ` + key + ` PRIMARY KEY, tenant ` + key + ` NOT NULL)`,
	} {
		if err := dbx.DDL(ctx, db, o.Dialect, q); err != nil {
			return nil, fmt.Errorf("groups: schema: %w", err)
		}
	}
	return s, nil
}

const tsLayout = "2006-01-02T15:04:05.000000000Z"

func parseTS(s string) time.Time { t, _ := time.Parse(tsLayout, s); return t }

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "grp_" + hex.EncodeToString(b)
}

func (s *Store) tell(ctx context.Context, tenant string, users []string, event string, v any, from string) {
	if s.o.Notifier == nil {
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	for _, u := range users {
		if u != from {
			_ = s.o.Notifier.Notify(ctx, tenant, u, event, raw, from)
		}
	}
}

func validName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 100 || !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: a group name is 1 to 100 characters", ErrInvalid)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: a group name cannot contain control characters", ErrInvalid)
		}
	}
	return name, nil
}

func (s *Store) users(list []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, u := range list {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		if !s.o.ValidUser(u) {
			return nil, fmt.Errorf("%w: %q is not a valid user name", ErrInvalid, u)
		}
		seen[u] = true
		out = append(out, u)
	}
	return out, nil
}

// roleOf returns the actor's role in a group of their tenant, or "" if they are
// not in it or it does not exist (the two look the same).
func (s *Store) roleOf(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, by Actor, id string) (string, error) {
	var role string
	err := q.QueryRowContext(ctx, s.rebind(`SELECT m.role FROM rtc_group_members m JOIN rtc_groups g ON g.id = m.group_id WHERE g.id = $1 AND g.tenant = $2 AND m.user_id = $3 AND NOT EXISTS (SELECT 1 FROM rtc_managed x WHERE x.id = g.id)`),
		id, by.Tenant, by.ID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return role, err
}

// Create makes a group with the caller as owner and the others as members.
func (s *Store) Create(ctx context.Context, by Actor, name string, members []string) (Group, error) {
	if by.ID == "" {
		return Group{}, ErrForbidden
	}
	name, err := validName(name)
	if err != nil {
		return Group{}, err
	}
	users, err := s.users(members)
	if err != nil {
		return Group{}, err
	}
	var others []string
	for _, u := range users {
		if u != by.ID {
			others = append(others, u)
		}
	}
	if len(others)+1 > s.o.MaxMembers {
		return Group{}, fmt.Errorf("%w: a group holds at most %d people", ErrLimit, s.o.MaxMembers)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Group{}, err
	}
	defer tx.Rollback()
	var owned int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_groups WHERE tenant = $1 AND owner = $2`), by.Tenant, by.ID).Scan(&owned); err != nil {
		return Group{}, err
	}
	if owned >= s.o.MaxOwned {
		return Group{}, fmt.Errorf("%w: you can own at most %d groups", ErrLimit, s.o.MaxOwned)
	}
	now := s.o.Now()
	g := Group{ID: newID(), Name: name, Owner: by.ID, CreatedAt: now, UpdatedAt: now}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_groups (id, tenant, name, owner, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)`),
		g.ID, by.Tenant, name, by.ID, now.Format(tsLayout), now.Format(tsLayout)); err != nil {
		return Group{}, err
	}
	g.Members = append(g.Members, Member{by.ID, RoleOwner, now})
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_group_members (group_id, user_id, role, added_at) VALUES ($1,$2,$3,$4)`), g.ID, by.ID, RoleOwner, now.Format(tsLayout)); err != nil {
		return Group{}, err
	}
	for _, u := range others {
		g.Members = append(g.Members, Member{u, RoleMember, now})
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_group_members (group_id, user_id, role, added_at) VALUES ($1,$2,$3,$4)`), g.ID, u, RoleMember, now.Format(tsLayout)); err != nil {
			return Group{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Group{}, err
	}
	s.tell(ctx, by.Tenant, others, "group.added", map[string]any{"group": g.ID, "name": name, "by": by.ID}, by.ID)
	return g, nil
}

func (s *Store) members(ctx context.Context, id string) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT user_id, role, added_at FROM rtc_group_members WHERE group_id = $1 ORDER BY added_at, user_id`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		var at string
		if err := rows.Scan(&m.User, &m.Role, &at); err != nil {
			return nil, err
		}
		m.AddedAt = parseTS(at)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) head(ctx context.Context, tenant, id string) (Group, error) {
	var g Group
	var c, u string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT id, name, owner, created_at, updated_at FROM rtc_groups WHERE id = $1 AND tenant = $2`), id, tenant).Scan(&g.ID, &g.Name, &g.Owner, &c, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrForbidden
	}
	g.CreatedAt, g.UpdatedAt = parseTS(c), parseTS(u)
	return g, err
}

// Get returns a group the caller belongs to.
func (s *Store) Get(ctx context.Context, by Actor, id string) (Group, error) {
	role, err := s.roleOf(ctx, s.db, by, id)
	if err != nil {
		return Group{}, err
	}
	if role == "" {
		return Group{}, ErrForbidden
	}
	g, err := s.head(ctx, by.Tenant, id)
	if err != nil {
		return Group{}, err
	}
	g.Members, err = s.members(ctx, id)
	return g, err
}

// Members returns who is in a group the caller belongs to.
func (s *Store) Members(ctx context.Context, by Actor, id string) ([]string, error) {
	g, err := s.Get(ctx, by, id)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(g.Members))
	for i, m := range g.Members {
		out[i] = m.User
	}
	return out, nil
}

// List returns the groups the caller belongs to, without their member lists.
func (s *Store) List(ctx context.Context, by Actor) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT g.id, g.name, g.owner, g.created_at, g.updated_at FROM rtc_groups g JOIN rtc_group_members m ON m.group_id = g.id WHERE g.tenant = $1 AND m.user_id = $2 AND NOT EXISTS (SELECT 1 FROM rtc_managed x WHERE x.id = g.id) ORDER BY g.created_at, g.id LIMIT 500`), by.Tenant, by.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		var c, u string
		if err := rows.Scan(&g.ID, &g.Name, &g.Owner, &c, &u); err != nil {
			return nil, err
		}
		g.CreatedAt, g.UpdatedAt = parseTS(c), parseTS(u)
		out = append(out, g)
	}
	return out, rows.Err()
}

func isAdmin(role string) bool { return role == RoleOwner || role == RoleAdmin }

// Rename changes a group's name. Owners and admins may.
func (s *Store) Rename(ctx context.Context, by Actor, id, name string) (Group, error) {
	name, err := validName(name)
	if err != nil {
		return Group{}, err
	}
	role, err := s.roleOf(ctx, s.db, by, id)
	if err != nil {
		return Group{}, err
	}
	if !isAdmin(role) {
		return Group{}, ErrForbidden
	}
	if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_groups SET name = $1, updated_at = $2 WHERE id = $3 AND tenant = $4`), name, s.o.Now().Format(tsLayout), id, by.Tenant); err != nil {
		return Group{}, err
	}
	g, err := s.Get(ctx, by, id)
	if err == nil {
		s.tell(ctx, by.Tenant, userNames(g.Members), "group.updated", map[string]any{"group": id, "name": name, "by": by.ID}, by.ID)
	}
	return g, err
}

func userNames(ms []Member) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.User
	}
	return out
}

// Add puts people in a group. Owners and admins may.
func (s *Store) Add(ctx context.Context, by Actor, id string, users []string) (Group, error) {
	list, err := s.users(users)
	if err != nil {
		return Group{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Group{}, err
	}
	defer tx.Rollback()
	role, err := s.roleOf(ctx, tx, by, id)
	if err != nil {
		return Group{}, err
	}
	if !isAdmin(role) {
		return Group{}, ErrForbidden
	}
	var n int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_group_members WHERE group_id = $1`), id).Scan(&n); err != nil {
		return Group{}, err
	}
	var added []string
	now := s.o.Now().Format(tsLayout)
	for _, u := range list {
		var exists int
		if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_group_members WHERE group_id = $1 AND user_id = $2`), id, u).Scan(&exists); err != nil {
			return Group{}, err
		}
		if exists > 0 {
			continue
		}
		if n+len(added)+1 > s.o.MaxMembers {
			return Group{}, fmt.Errorf("%w: a group holds at most %d people", ErrLimit, s.o.MaxMembers)
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_group_members (group_id, user_id, role, added_at) VALUES ($1,$2,$3,$4)`), id, u, RoleMember, now); err != nil {
			return Group{}, err
		}
		added = append(added, u)
	}
	if err := tx.Commit(); err != nil {
		return Group{}, err
	}
	g, err := s.Get(ctx, by, id)
	if err != nil {
		return Group{}, err
	}
	if len(added) > 0 {
		s.tell(ctx, by.Tenant, added, "group.added", map[string]any{"group": id, "name": g.Name, "by": by.ID}, by.ID)
		s.tell(ctx, by.Tenant, userNames(g.Members), "group.members_added", map[string]any{"group": id, "users": added, "by": by.ID}, by.ID)
	}
	return g, nil
}

// Remove takes people out of a group. Owners may remove anyone but themselves;
// admins may remove members; anyone may remove themselves, except the owner,
// who must hand the group over or delete it.
func (s *Store) Remove(ctx context.Context, by Actor, id string, users []string) (Group, error) {
	list, err := s.users(users)
	if err != nil {
		return Group{}, err
	}
	role, err := s.roleOf(ctx, s.db, by, id)
	if err != nil {
		return Group{}, err
	}
	if role == "" {
		return Group{}, ErrForbidden
	}
	before, err := s.members(ctx, id)
	if err != nil {
		return Group{}, err
	}
	roles := map[string]string{}
	for _, m := range before {
		roles[m.User] = m.Role
	}
	var gone []string
	for _, u := range list {
		target, in := roles[u]
		switch {
		case !in:
			continue
		case target == RoleOwner:
			return Group{}, fmt.Errorf("%w: the owner cannot be removed; hand the group over or delete it", ErrForbidden)
		case u == by.ID: // leaving
		case role == RoleOwner:
		case role == RoleAdmin && target == RoleMember:
		default:
			return Group{}, ErrForbidden
		}
		gone = append(gone, u)
	}
	for _, u := range gone {
		if _, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_group_members WHERE group_id = $1 AND user_id = $2`), id, u); err != nil {
			return Group{}, err
		}
	}
	if len(gone) > 0 {
		_, _ = s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_groups SET updated_at = $1 WHERE id = $2`), s.o.Now().Format(tsLayout), id)
	}
	left, err := s.members(ctx, id)
	if err != nil {
		return Group{}, err
	}
	if len(gone) > 0 && s.o.OnRemove != nil {
		s.o.OnRemove(ctx, by.Tenant, id, gone)
	}
	s.tell(ctx, by.Tenant, gone, "group.removed", map[string]any{"group": id, "by": by.ID}, by.ID)
	s.tell(ctx, by.Tenant, userNames(left), "group.members_removed", map[string]any{"group": id, "users": gone, "by": by.ID}, by.ID)
	if r := roles[by.ID]; r != "" && contains(gone, by.ID) {
		return Group{ID: id}, nil // the caller has left: they can no longer see it
	}
	return s.Get(ctx, by, id)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// SetRole makes a member an admin, or an admin a member. Only the owner may.
func (s *Store) SetRole(ctx context.Context, by Actor, id, user, role string) (Group, error) {
	if role != RoleAdmin && role != RoleMember {
		return Group{}, fmt.Errorf("%w: a role is admin or member", ErrInvalid)
	}
	mine, err := s.roleOf(ctx, s.db, by, id)
	if err != nil {
		return Group{}, err
	}
	if mine != RoleOwner {
		return Group{}, ErrForbidden
	}
	target, err := s.roleOf(ctx, s.db, Actor{ID: user, Tenant: by.Tenant}, id)
	if err != nil {
		return Group{}, err
	}
	if target == "" {
		return Group{}, fmt.Errorf("%w: %q is not in the group", ErrInvalid, user)
	}
	if target == RoleOwner {
		return Group{}, fmt.Errorf("%w: hand the group over instead", ErrInvalid)
	}
	if _, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_group_members SET role = $1 WHERE group_id = $2 AND user_id = $3`), role, id, user); err != nil {
		return Group{}, err
	}
	s.tell(ctx, by.Tenant, []string{user}, "group.role", map[string]any{"group": id, "role": role, "by": by.ID}, by.ID)
	return s.Get(ctx, by, id)
}

// Transfer hands a group to another member; the old owner becomes an admin.
func (s *Store) Transfer(ctx context.Context, by Actor, id, to string) (Group, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Group{}, err
	}
	defer tx.Rollback()
	mine, err := s.roleOf(ctx, tx, by, id)
	if err != nil {
		return Group{}, err
	}
	if mine != RoleOwner {
		return Group{}, ErrForbidden
	}
	target, err := s.roleOf(ctx, tx, Actor{ID: to, Tenant: by.Tenant}, id)
	if err != nil {
		return Group{}, err
	}
	if target == "" || to == by.ID {
		return Group{}, fmt.Errorf("%w: choose another member of the group", ErrInvalid)
	}
	var owned int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_groups WHERE tenant = $1 AND owner = $2`), by.Tenant, to).Scan(&owned); err != nil {
		return Group{}, err
	}
	if owned >= s.o.MaxOwned {
		return Group{}, fmt.Errorf("%w: %q already owns %d groups", ErrLimit, to, s.o.MaxOwned)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE rtc_group_members SET role = $1 WHERE group_id = $2 AND user_id = $3`, []any{RoleAdmin, id, by.ID}},
		{`UPDATE rtc_group_members SET role = $1 WHERE group_id = $2 AND user_id = $3`, []any{RoleOwner, id, to}},
		{`UPDATE rtc_groups SET owner = $1, updated_at = $2 WHERE id = $3`, []any{to, s.o.Now().Format(tsLayout), id}},
	} {
		if _, err := tx.ExecContext(ctx, s.rebind(q.sql), q.args...); err != nil {
			return Group{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Group{}, err
	}
	g, err := s.Get(ctx, by, id)
	if err == nil {
		s.tell(ctx, by.Tenant, userNames(g.Members), "group.owner", map[string]any{"group": id, "owner": to, "by": by.ID}, by.ID)
	}
	return g, err
}

// Delete removes a group. Only the owner may.
func (s *Store) Delete(ctx context.Context, by Actor, id string) error {
	g, err := s.Get(ctx, by, id)
	if err != nil {
		return err
	}
	if g.Owner != by.ID {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM rtc_group_members WHERE group_id = $1`), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM rtc_groups WHERE id = $1 AND tenant = $2`), id, by.Tenant); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.o.OnDelete != nil {
		s.o.OnDelete(ctx, by.Tenant, id)
	}
	s.tell(ctx, by.Tenant, userNames(g.Members), "group.deleted", map[string]any{"group": id, "name": g.Name, "by": by.ID}, by.ID)
	return nil
}

// Roster returns who is in a group of the tenant and in what role, in one query.
// It checks nothing about the caller: the server uses it to decide for itself.
// A group that does not exist has an empty roster.
func (s *Store) Roster(ctx context.Context, tenant, id string) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT m.user_id, m.role FROM rtc_group_members m JOIN rtc_groups g ON g.id = m.group_id WHERE g.id = $1 AND g.tenant = $2`), id, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.User, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

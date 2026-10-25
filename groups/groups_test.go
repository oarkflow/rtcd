package groups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

var bg = context.Background()

type bus struct {
	mu sync.Mutex
	ev []string
}

func (b *bus) Notify(_ context.Context, tenant, user, event string, _ json.RawMessage, _ string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ev = append(b.ev, tenant+"/"+user+"/"+event)
	return nil
}
func (b *bus) got(tenant, user, event string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range b.ev {
		if e == tenant+"/"+user+"/"+event {
			return true
		}
	}
	return false
}

func setup(t *testing.T, mod func(*Options)) (*Store, *bus) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "g.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	b := &bus{}
	o := Options{Dialect: "sqlite", Notifier: b}
	if mod != nil {
		mod(&o)
	}
	s, err := Open(bg, db, o)
	if err != nil {
		t.Fatal(err)
	}
	return s, b
}

var ada, bob, cy, eve = Actor{ID: "ada", Tenant: "t"}, Actor{ID: "bob", Tenant: "t"}, Actor{ID: "cy", Tenant: "t"}, Actor{ID: "eve", Tenant: "t"}

func roles(g Group) string {
	var parts []string
	for _, m := range g.Members {
		parts = append(parts, m.User+":"+m.Role)
	}
	return strings.Join(parts, ",")
}

func TestCreatingAGroupMakesTheCreatorOwner(t *testing.T) {
	s, b := setup(t, nil)
	g, err := s.Create(bg, ada, "  Design team  ", []string{"bob", "cy", "bob", "ada", " "})
	if err != nil || g.Name != "Design team" || g.Owner != "ada" || len(g.Members) != 3 {
		t.Fatalf("%+v %v", g, err)
	}
	if got := roles(g); got != "ada:owner,bob:member,cy:member" {
		t.Fatalf("%s", got)
	}
	if !b.got("t", "bob", "group.added") || b.got("t", "ada", "group.added") {
		t.Fatalf("%v", b.ev)
	}
	for _, name := range []string{"", "   ", strings.Repeat("x", 101), "a\x00b", "a\nb"} {
		if _, err := s.Create(bg, ada, name, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if _, err := s.Create(bg, ada, "g", []string{"a\x1fb"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a bad member name: %v", err)
	}
	if _, err := s.Create(bg, Actor{Tenant: "t"}, "g", nil); !errors.Is(err, ErrForbidden) {
		t.Errorf("an anonymous creator: %v", err)
	}
}

func TestOnlyMembersSeeAGroupAndNonexistentLooksTheSame(t *testing.T) {
	s, _ := setup(t, nil)
	g, _ := s.Create(bg, ada, "secret", []string{"bob"})
	if _, err := s.Get(bg, bob, g.ID); err != nil {
		t.Fatal(err)
	}
	_, e1 := s.Get(bg, eve, g.ID)
	_, e2 := s.Get(bg, eve, "grp_nope")
	if !errors.Is(e1, ErrForbidden) || e1.Error() != e2.Error() {
		t.Fatalf("a stranger can tell a group exists: %v vs %v", e1, e2)
	}
	if l, _ := s.List(bg, eve); len(l) != 0 {
		t.Fatalf("eve lists %+v", l)
	}
	if l, _ := s.List(bg, bob); len(l) != 1 || l[0].ID != g.ID || len(l[0].Members) != 0 {
		t.Fatalf("bob lists %+v", l)
	}
	if ms, err := s.Members(bg, bob, g.ID); err != nil || len(ms) != 2 {
		t.Fatalf("%v %v", ms, err)
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	s, _ := setup(t, nil)
	g, _ := s.Create(bg, ada, "acme", []string{"bob"})
	other := func(a Actor) Actor { a.Tenant = "other"; return a }
	for name, err := range map[string]error{
		"get":    func() error { _, e := s.Get(bg, other(bob), g.ID); return e }(),
		"rename": func() error { _, e := s.Rename(bg, other(ada), g.ID, "x"); return e }(),
		"add":    func() error { _, e := s.Add(bg, other(ada), g.ID, []string{"z"}); return e }(),
		"remove": func() error { _, e := s.Remove(bg, other(ada), g.ID, []string{"bob"}); return e }(),
		"delete": s.Delete(bg, other(ada), g.ID),
	} {
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("%s across tenants: %v", name, err)
		}
	}
	if l, _ := s.List(bg, other(ada)); len(l) != 0 {
		t.Fatalf("%+v", l)
	}
	// The same user name in another tenant owns a different group.
	h, err := s.Create(bg, other(ada), "theirs", nil)
	if err != nil || h.ID == g.ID {
		t.Fatalf("%+v %v", h, err)
	}
	if got, _ := s.Get(bg, ada, g.ID); got.Name != "acme" || len(got.Members) != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestWhoMayChangeAGroup(t *testing.T) {
	s, b := setup(t, nil)
	g, _ := s.Create(bg, ada, "g", []string{"bob", "cy"})
	// A plain member can do none of it.
	if _, err := s.Rename(bg, bob, g.ID, "x"); !errors.Is(err, ErrForbidden) {
		t.Errorf("member rename: %v", err)
	}
	if _, err := s.Add(bg, bob, g.ID, []string{"dan"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("member add: %v", err)
	}
	if _, err := s.Remove(bg, bob, g.ID, []string{"cy"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("member remove: %v", err)
	}
	if _, err := s.SetRole(bg, bob, g.ID, "cy", RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Errorf("member set role: %v", err)
	}
	if err := s.Delete(bg, bob, g.ID); !errors.Is(err, ErrForbidden) {
		t.Errorf("member delete: %v", err)
	}
	// The owner promotes bob; now bob can rename and add, but cannot remove an admin or the owner, or promote.
	if g, err := s.SetRole(bg, ada, g.ID, "bob", RoleAdmin); err != nil || roles(g) != "ada:owner,bob:admin,cy:member" {
		t.Fatalf("%s %v", roles(g), err)
	}
	if !b.got("t", "bob", "group.role") {
		t.Error("bob was not told")
	}
	if g, err := s.Rename(bg, bob, g.ID, "renamed"); err != nil || g.Name != "renamed" {
		t.Fatalf("%+v %v", g, err)
	}
	if g, err := s.Add(bg, bob, g.ID, []string{"dan"}); err != nil || len(g.Members) != 4 {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := s.Remove(bg, bob, g.ID, []string{"ada"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("an admin removed the owner: %v", err)
	}
	if _, err := s.SetRole(bg, bob, g.ID, "cy", RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Errorf("an admin promoted someone: %v", err)
	}
	if g, err := s.Remove(bg, bob, g.ID, []string{"dan"}); err != nil || len(g.Members) != 3 {
		t.Fatalf("an admin removing a member: %+v %v", g, err)
	}
	// Two admins cannot remove each other.
	_, _ = s.SetRole(bg, ada, g.ID, "cy", RoleAdmin)
	if _, err := s.Remove(bg, bob, g.ID, []string{"cy"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("an admin removed an admin: %v", err)
	}
	if !b.got("t", "cy", "group.role") {
		t.Error("cy was not told")
	}
	if _, err := s.SetRole(bg, ada, g.ID, "ada", RoleMember); !errors.Is(err, ErrInvalid) {
		t.Errorf("the owner demoted themselves: %v", err)
	}
	if _, err := s.SetRole(bg, ada, g.ID, "bob", "owner"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a role of owner: %v", err)
	}
	if _, err := s.SetRole(bg, ada, g.ID, "stranger", RoleAdmin); !errors.Is(err, ErrInvalid) {
		t.Errorf("a role for a non-member: %v", err)
	}
}

func TestLeavingAndTheOwner(t *testing.T) {
	s, _ := setup(t, nil)
	g, _ := s.Create(bg, ada, "g", []string{"bob", "cy"})
	// A member can leave; then they cannot see the group.
	if _, err := s.Remove(bg, bob, g.ID, []string{"bob"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(bg, bob, g.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob still sees the group: %v", err)
	}
	// The owner cannot leave, or be removed, but can hand over.
	if _, err := s.Remove(bg, ada, g.ID, []string{"ada"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("the owner left: %v", err)
	}
	if _, err := s.Transfer(bg, ada, g.ID, "bob"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("handed over to a non-member: %v", err)
	}
	if _, err := s.Transfer(bg, ada, g.ID, "ada"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("handed over to themselves: %v", err)
	}
	if _, err := s.Transfer(bg, cy, g.ID, "cy"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a member handed over: %v", err)
	}
	h, err := s.Transfer(bg, ada, g.ID, "cy")
	if err != nil || h.Owner != "cy" || roles(h) != "ada:admin,cy:owner" {
		t.Fatalf("%s %v", roles(h), err)
	}
	if err := s.Delete(bg, ada, g.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("the old owner deleted the group: %v", err)
	}
	if _, err := s.Remove(bg, cy, g.ID, []string{"ada"}); err != nil {
		t.Fatalf("the new owner removing the old: %v", err)
	}
	if err := s.Delete(bg, cy, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(bg, cy, g.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("the group survived: %v", err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM rtc_group_members`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d membership rows left behind", n)
	}
}

func TestLimits(t *testing.T) {
	s, _ := setup(t, func(o *Options) { o.MaxOwned = 2; o.MaxMembers = 3 })
	g, _ := s.Create(bg, ada, "one", []string{"bob"})
	_, _ = s.Create(bg, ada, "two", nil)
	if _, err := s.Create(bg, ada, "three", nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("a third group: %v", err)
	}
	if _, err := s.Create(bg, bob, "big", []string{"a", "b", "c"}); !errors.Is(err, ErrLimit) {
		t.Fatalf("an oversize group: %v", err)
	}
	if _, err := s.Add(bg, ada, g.ID, []string{"cy", "dan"}); !errors.Is(err, ErrLimit) {
		t.Fatalf("growing past the cap: %v", err)
	}
	if got, _ := s.Get(bg, ada, g.ID); len(got.Members) != 2 {
		t.Fatalf("a refused add changed the group: %d", len(got.Members))
	}
	if _, err := s.Add(bg, ada, g.ID, []string{"cy", "bob", "cy"}); err != nil { // bob already there, cy once
		t.Fatal(err)
	}
	// Handing a group to someone at their limit is refused.
	_, _ = s.Create(bg, cy, "c1", nil)
	_, _ = s.Create(bg, cy, "c2", nil)
	if _, err := s.Transfer(bg, ada, g.ID, "cy"); !errors.Is(err, ErrLimit) {
		t.Fatalf("handed to someone at their limit: %v", err)
	}
}

func TestConcurrentAddsRespectTheCap(t *testing.T) {
	s, _ := setup(t, func(o *Options) { o.MaxMembers = 10 })
	g, _ := s.Create(bg, ada, "g", nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = s.Add(bg, ada, g.ID, []string{"u" + string(rune('a'+i))})
		}(i)
	}
	wg.Wait()
	got, _ := s.Get(bg, ada, g.ID)
	if len(got.Members) != 10 {
		t.Fatalf("%d members with a cap of 10", len(got.Members))
	}
}

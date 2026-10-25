package calls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type event struct{ topic, name, from string }

type bus struct {
	mu sync.Mutex
	ev []event
	// payloads of the last event of each name
	last map[string]json.RawMessage
}

func (b *bus) Notify(_ context.Context, tenant, user, name string, data json.RawMessage, from string) error {
	topic := UserTopic(tenant, user)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ev = append(b.ev, event{topic, name, from})
	if b.last == nil {
		b.last = map[string]json.RawMessage{}
	}
	b.last[name] = data
	return nil
}

func (b *bus) got(topic, name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range b.ev {
		if e.topic == topic && e.name == name {
			return true
		}
	}
	return false
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup(t *testing.T, mod func(*Options)) (*Store, *bus, *clock) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "c.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	b, clk := &bus{}, &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	o := Options{Dialect: "sqlite", Notifier: b, Now: clk.now, ICE: ICEConfig{STUN: []string{"stun:s.example:3478"}, TURN: []string{"turn:t.example:3478"}, Secret: "s3cret"}}
	if mod != nil {
		mod(&o)
	}
	s, err := Open(context.Background(), db, o)
	if err != nil {
		t.Fatal(err)
	}
	return s, b, clk
}

var ctx = context.Background()
var ada, bob, eve = Actor{ID: "ada"}, Actor{ID: "bob"}, Actor{ID: "eve"}

func TestP2PCallLifecycle(t *testing.T) {
	s, b, _ := setup(t, nil)
	c, err := s.Start(ctx, ada, []string{"bob"}, "video", P2P)
	if err != nil || c.Status != Ringing {
		t.Fatalf("start: %v %+v", err, c)
	}
	if !b.got("user:bob", "call.incoming") || b.got("user:ada", "call.incoming") {
		t.Fatalf("ringing went to the wrong people: %v", b.ev)
	}
	// The caller may send an offer while it rings; the stranger may not signal at all.
	if err := s.Signal(ctx, ada, c.ID, "bob", "offer", json.RawMessage(`{"sdp":"v=0"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Signal(ctx, eve, c.ID, "bob", "offer", json.RawMessage(`{}`)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stranger signal: %v", err)
	}
	// The callee cannot signal before joining.
	if err := s.Signal(ctx, bob, c.ID, "ada", "answer", json.RawMessage(`{}`)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("callee signal before answering: %v", err)
	}
	if _, err := s.Answer(ctx, ada, c.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("caller answering own call: %v", err)
	}
	if c, err = s.Answer(ctx, bob, c.ID); err != nil || c.Status != Active {
		t.Fatalf("answer: %v %+v", err, c)
	}
	if err := s.Signal(ctx, bob, c.ID, "ada", "answer", json.RawMessage(`{"sdp":"v=0"}`)); err != nil {
		t.Fatal(err)
	}
	if !b.got("user:ada", "call.signal") {
		t.Fatal("answer was not relayed")
	}
	var sig struct {
		From string `json:"from"`
		Type string `json:"type"`
	}
	_ = json.Unmarshal(b.last["call.signal"], &sig)
	if sig.From != "bob" || sig.Type != "answer" {
		t.Fatalf("relayed signal %+v", sig)
	}
	if c, err = s.End(ctx, bob, c.ID); err != nil || c.Status != Ended {
		t.Fatalf("end: %v %+v", err, c)
	}
	if !b.got(UserTopic("", "ada"), "call.ended") {
		t.Fatal("caller was not told")
	}
	if err := s.Signal(ctx, ada, c.ID, "bob", "candidate", json.RawMessage(`{}`)); !errors.Is(err, ErrState) {
		t.Fatalf("signal after end: %v", err)
	}
}

func TestStrangersAndUnknownIDsLookAlike(t *testing.T) {
	s, _, _ := setup(t, nil)
	c, _ := s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	_, e1 := s.Get(ctx, eve, c.ID)
	_, e2 := s.Get(ctx, eve, "call_nope")
	if !errors.Is(e1, ErrForbidden) || !errors.Is(e2, ErrForbidden) {
		t.Fatalf("probing: %v / %v", e1, e2)
	}
	// Another tenant's "ada" is not this call's ada, whatever the call's tenant.
	if _, err := s.Get(ctx, Actor{ID: "ada", Tenant: "other"}, c.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a different tenant's user saw the call: %v", err)
	}
}

func TestTenantsWithTheSameUserNamesNeverShareCallsOrEvents(t *testing.T) {
	s, b, _ := setup(t, nil)
	acme := func(id string) Actor { return Actor{ID: id, Tenant: "acme"} }
	zeta := func(id string) Actor { return Actor{ID: id, Tenant: "zeta"} }
	ca, err := s.Start(ctx, acme("ada"), []string{"bob"}, "video", P2P)
	if err != nil {
		t.Fatal(err)
	}
	if !b.got(UserTopic("acme", "bob"), "call.incoming") {
		t.Fatal("acme's bob was not rung on a tenant-scoped topic")
	}
	if b.got(UserTopic("zeta", "bob"), "call.incoming") || b.got("user:bob", "call.incoming") {
		t.Fatal("the event leaked to another tenant's bob")
	}
	// zeta's ada and bob have the same names but cannot touch acme's call.
	if _, err := s.Get(ctx, zeta("bob"), ca.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("get across tenants: %v", err)
	}
	if _, err := s.Answer(ctx, zeta("bob"), ca.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("answer across tenants: %v", err)
	}
	if err := s.Relay(ctx, zeta("ada"), ca.ID, "bob", "x"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("relay across tenants: %v", err)
	}
	if err := s.Signal(ctx, zeta("ada"), ca.ID, "bob", "offer", json.RawMessage(`{}`)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("signal across tenants: %v", err)
	}
	if _, err := s.End(ctx, zeta("ada"), ca.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("end across tenants: %v", err)
	}
	if got, _ := s.Get(ctx, acme("ada"), ca.ID); got.Status == Ended {
		t.Fatal("the other tenant ended the call")
	}
}

func TestDeclineMissedAndCancel(t *testing.T) {
	s, _, clk := setup(t, nil)
	c, _ := s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	if c, _ = s.Decline(ctx, bob, c.ID); c.Status != Ended || c.Reason != "declined" {
		t.Fatalf("decline: %+v", c)
	}

	c, _ = s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	if c, _ = s.End(ctx, ada, c.ID); c.Status != Ended || c.Reason != "cancelled" {
		t.Fatalf("cancel while ringing: %+v", c)
	}

	c, _ = s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	clk.t = clk.t.Add(time.Minute)
	if _, err := s.Answer(ctx, bob, c.ID); !errors.Is(err, ErrState) {
		t.Fatalf("answering a missed call: %v", err)
	}
	got, _ := s.Get(ctx, ada, c.ID)
	if got.Status != Ended || got.Reason != "missed" {
		t.Fatalf("missed: %+v", got)
	}
}

func TestSweepEndsStaleRinging(t *testing.T) {
	s, b, clk := setup(t, nil)
	_, _ = s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	_, _ = s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	clk.t = clk.t.Add(2 * time.Minute)
	n, err := s.Sweep(ctx)
	if err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if !b.got("user:bob", "call.ended") {
		t.Fatal("callee not told it was missed")
	}
}

func TestGroupCall(t *testing.T) {
	s, _, _ := setup(t, nil)
	if _, err := s.Start(ctx, ada, []string{"bob", "cy"}, "video", P2P); !errors.Is(err, ErrInvalid) {
		t.Fatalf("3-way p2p: %v", err)
	}
	c, err := s.Start(ctx, ada, []string{"bob", "cy"}, "video", SFU)
	if err != nil || c.Room != c.ID {
		t.Fatalf("group: %v %+v", err, c)
	}
	_, _ = s.Answer(ctx, bob, c.ID)
	if c, _ = s.Decline(ctx, Actor{ID: "cy"}, c.ID); c.Status == Ended {
		t.Fatal("one decline must not end a group call")
	}
	if c, _ = s.End(ctx, bob, c.ID); c.Status == Ended {
		t.Fatal("a member leaving must not end the call while the initiator is in it")
	}
	if c, _ = s.End(ctx, ada, c.ID); c.Status != Ended {
		t.Fatalf("initiator ends for all: %+v", c)
	}
	// Signals are for p2p; an sfu call talks to the server.
	c, _ = s.Start(ctx, ada, []string{"bob"}, "video", SFU)
	_, _ = s.Answer(ctx, bob, c.ID)
	if err := s.Signal(ctx, ada, c.ID, "bob", "offer", json.RawMessage(`{}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relay in an sfu call: %v", err)
	}
}

func TestValidation(t *testing.T) {
	s, _, _ := setup(t, func(o *Options) {
		o.CanCall = func(_ context.Context, _ Actor, to string) error {
			if to == "blocked" {
				return errors.New("blocked")
			}
			return nil
		}
	})
	for name, f := range map[string]func() error{
		"anonymous":    func() error { _, err := s.Start(ctx, Actor{}, []string{"bob"}, "audio", P2P); return err },
		"nobody":       func() error { _, err := s.Start(ctx, ada, nil, "audio", P2P); return err },
		"self":         func() error { _, err := s.Start(ctx, ada, []string{"ada"}, "audio", P2P); return err },
		"bad kind":     func() error { _, err := s.Start(ctx, ada, []string{"bob"}, "hologram", P2P); return err },
		"bad mode":     func() error { _, err := s.Start(ctx, ada, []string{"bob"}, "audio", "mesh"); return err },
		"blocked user": func() error { _, err := s.Start(ctx, ada, []string{"blocked"}, "audio", P2P); return err },
	} {
		if f() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	c, _ := s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	_, _ = s.Answer(ctx, bob, c.ID)
	big := json.RawMessage(`"` + strings.Repeat("x", MaxSignal) + `"`)
	for name, tc := range map[string]struct {
		typ  string
		data json.RawMessage
		to   string
	}{
		"oversize": {"offer", big, "bob"}, "bad json": {"offer", json.RawMessage(`{`), "bob"},
		"bad type": {"exec", json.RawMessage(`{}`), "bob"}, "to self": {"offer", json.RawMessage(`{}`), "ada"},
		"to stranger": {"offer", json.RawMessage(`{}`), "eve"},
	} {
		if s.Signal(ctx, ada, c.ID, tc.to, tc.typ, tc.data) == nil {
			t.Errorf("signal %s was accepted", name)
		}
	}
}

func TestTURNCredentials(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	servers := ICEConfig{STUN: []string{"stun:a"}, TURN: []string{"turn:b"}, Secret: "k", TTL: 10 * time.Minute}.Servers("ada", now)
	if len(servers) != 2 || servers[0].Credential != "" {
		t.Fatalf("servers %+v", servers)
	}
	turn := servers[1]
	if turn.Username != strconv.FormatInt(now.Add(10*time.Minute).Unix(), 10)+":ada" {
		t.Fatalf("username %q", turn.Username)
	}
	mac := hmac.New(sha1.New, []byte("k"))
	mac.Write([]byte(turn.Username))
	if turn.Credential != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("credential is not HMAC-SHA1 of the username (coturn REST scheme)")
	}
	if got := (ICEConfig{TURN: []string{"turn:b"}}).Servers("ada", now); len(got) != 0 {
		t.Fatalf("TURN without a secret must not be offered: %+v", got)
	}
}

func TestEncryptionIsRequiredWhenConfigured(t *testing.T) {
	s, _, _ := setup(t, func(o *Options) { o.RequireE2EE = true })
	c, err := s.Start(ctx, ada, []string{"bob"}, "video", P2P)
	if err != nil || !c.E2EE {
		t.Fatalf("a call on an encryption-required server must be encrypted: %v %+v", err, c)
	}
	got, _ := s.Get(ctx, bob, c.ID)
	if !got.E2EE {
		t.Fatal("the encryption flag was not stored")
	}
	off := false
	if _, err := s.StartCall(ctx, ada, []string{"bob"}, "video", P2P, &off); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a plaintext call was allowed: %v", err)
	}
}

func TestPlaintextOnlyWhenTheServerAllowsIt(t *testing.T) {
	s, _, _ := setup(t, nil) // RequireE2EE off
	c, _ := s.Start(ctx, ada, []string{"bob"}, "video", P2P)
	if c.E2EE {
		t.Fatal("encryption should follow the server's policy")
	}
	on := true
	c, _ = s.StartCall(ctx, ada, []string{"bob"}, "video", P2P, &on)
	if !c.E2EE {
		t.Fatal("an explicit request for encryption was ignored")
	}
}

func TestKeyMessagesAreRelayedOpaquelyAndOnlyBetweenParticipants(t *testing.T) {
	s, b, _ := setup(t, func(o *Options) { o.RequireE2EE = true })
	c, _ := s.Start(ctx, ada, []string{"bob"}, "video", SFU)
	// The invitee has not joined yet: the caller may send (it is how the first key
	// reaches them), the invitee may not until they answer.
	if err := s.Relay(ctx, ada, c.ID, "bob", `{"v":1}`); err != nil {
		t.Fatal(err)
	}
	if err := s.Relay(ctx, bob, c.ID, "ada", `{"v":1}`); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an invitee relayed before joining: %v", err)
	}
	_, _ = s.Answer(ctx, bob, c.ID)
	if err := s.Relay(ctx, bob, c.ID, "ada", `{"v":1}`); err != nil {
		t.Fatal(err)
	}
	// The sender is stamped by the server; the payload is delivered untouched.
	var got struct{ From, Data string }
	_ = json.Unmarshal(b.last["call.e2ee"], &got)
	if got.From != "bob" || got.Data != `{"v":1}` {
		t.Fatalf("delivered %+v", got)
	}
	if !b.got("user:ada", "call.e2ee") {
		t.Fatal("not delivered to ada")
	}
	// A stranger, an unknown call, yourself, and oversize or empty messages.
	for name, err := range map[string]error{
		"stranger":      s.Relay(ctx, eve, c.ID, "ada", "x"),
		"to a stranger": s.Relay(ctx, ada, c.ID, "eve", "x"),
		"to yourself":   s.Relay(ctx, ada, c.ID, "ada", "x"),
		"empty":         s.Relay(ctx, ada, c.ID, "bob", ""),
		"oversize":      s.Relay(ctx, ada, c.ID, "bob", strings.Repeat("x", MaxRelay+1)),
		"unknown call":  s.Relay(ctx, ada, "call_nope", "bob", "x"),
	} {
		if err == nil {
			t.Errorf("%s was relayed", name)
		}
	}
	_, _ = s.End(ctx, ada, c.ID)
	if err := s.Relay(ctx, ada, c.ID, "bob", "x"); !errors.Is(err, ErrState) {
		t.Fatalf("relay after the call ended: %v", err)
	}
}

func TestRelayAndSignalNeverTouchTheDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "c.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	b := &bus{}
	s, err := Open(ctx, db, Options{Dialect: "sqlite", Notifier: b})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Start(ctx, ada, []string{"bob"}, "video", SFU)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Answer(ctx, bob, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peek(ctx, ada, c.ID); err != nil { // warm the cache
		t.Fatal(err)
	}
	// With the database gone, everything that only reads who is in the call still
	// works: that is the relay path, and it must not queue behind database work.
	_ = db.Close()
	for i := 0; i < 100; i++ {
		if err := s.Relay(ctx, ada, c.ID, "bob", "k"); err != nil {
			t.Fatalf("relay %d needed the database: %v", i, err)
		}
		v, err := s.Peek(ctx, bob, c.ID)
		if err != nil || v.State != "joined" || v.Mode != SFU {
			t.Fatalf("peek %d: %+v %v", i, v, err)
		}
	}
	// A stranger is still a stranger from the cache.
	if _, err := s.Peek(ctx, eve, c.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a stranger saw the call: %v", err)
	}
	// Anything that changes the call does need it.
	if _, err := s.End(ctx, ada, c.ID); err == nil {
		t.Fatal("ending a call without a database cannot have succeeded")
	}
}

func TestACallChangeIsSeenAtOnce(t *testing.T) {
	s, _, _ := setup(t, nil)
	c, _ := s.Start(ctx, ada, []string{"bob"}, "video", SFU)
	if v, _ := s.Peek(ctx, bob, c.ID); v.State != "invited" || v.Status != Ringing {
		t.Fatalf("%+v", v)
	}
	_, _ = s.Answer(ctx, bob, c.ID)
	if v, _ := s.Peek(ctx, bob, c.ID); v.State != "joined" || v.Status != Active {
		t.Fatalf("the cache served an old state after an answer: %+v", v)
	}
	_, _ = s.End(ctx, ada, c.ID)
	if v, _ := s.Peek(ctx, bob, c.ID); v.Status != Ended {
		t.Fatalf("the cache served an old state after the call ended: %+v", v)
	}
	if err := s.Relay(ctx, ada, c.ID, "bob", "x"); !errors.Is(err, ErrState) {
		t.Fatalf("relay into an ended call: %v", err)
	}
}

func TestARingingCallStillTimesOutWhenServedFromMemory(t *testing.T) {
	s, _, clk := setup(t, nil)
	c, _ := s.Start(ctx, ada, []string{"bob"}, "audio", P2P)
	if _, err := s.Peek(ctx, bob, c.ID); err != nil { // cached
		t.Fatal(err)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if v, _ := s.Peek(ctx, bob, c.ID); v.Status != Ended {
		t.Fatalf("a call that rang for two minutes is still %s", v.Status)
	}
}

func TestInvitingPeopleIntoAGroupCall(t *testing.T) {
	s, b, _ := setup(t, func(o *Options) { o.MaxInvitees = 3 })
	cy := Actor{ID: "cy"}
	c, _ := s.Start(ctx, ada, []string{"bob"}, "video", SFU)
	// Only someone who has joined may invite; p2p calls cannot grow.
	if _, err := s.Invite(ctx, bob, c.ID, []string{"cy"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an invitee who has not answered invited someone: %v", err)
	}
	got, err := s.Invite(ctx, ada, c.ID, []string{"cy", "bob", "ada", " "})
	if err != nil || len(got.Participants) != 3 {
		t.Fatalf("%+v %v", got, err)
	}
	if !b.got("user:cy", "call.incoming") {
		t.Fatal("cy was not rung")
	}
	if st, _ := got.role("cy"); st != "invited" {
		t.Fatalf("cy is %s", st)
	}
	if _, err := s.Answer(ctx, cy, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Invite(ctx, ada, c.ID, []string{"d1", "d2", "d3"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the call grew past its cap: %v", err)
	}
	p, _ := s.Start(ctx, ada, []string{"bob"}, "video", P2P)
	if _, err := s.Invite(ctx, ada, p.ID, []string{"cy"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a p2p call took a third person: %v", err)
	}
	// Somebody who declined can be asked again.
	_, _ = s.Decline(ctx, bob, c.ID)
	again, err := s.Invite(ctx, ada, c.ID, []string{"bob"})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := again.role("bob"); st != "invited" {
		t.Fatalf("bob is %s after being asked again", st)
	}
}

func TestGroupCallsAreFoundAndJoinedByMembers(t *testing.T) {
	s, _, _ := setup(t, nil)
	c, err := s.StartWith(ctx, ada, StartOptions{To: []string{"bob"}, Kind: "video", Mode: SFU, Group: "grp_1"})
	if err != nil || c.Group != "grp_1" {
		t.Fatalf("%+v %v", c, err)
	}
	found, ok, err := s.ActiveGroupCall(ctx, "", "grp_1")
	if err != nil || !ok || found.ID != c.ID {
		t.Fatalf("%+v %v %v", found, ok, err)
	}
	if _, ok, _ := s.ActiveGroupCall(ctx, "", "grp_other"); ok {
		t.Fatal("found a call for another group")
	}
	// A member who was not invited at the start is rung into the call.
	got, err := s.JoinGroupCall(ctx, Actor{ID: "cy"}, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := got.role("cy"); st != "invited" {
		t.Fatalf("cy is %s", st)
	}
	if _, err := s.JoinGroupCall(ctx, Actor{ID: "cy", Tenant: "other"}, c.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("another tenant's user joined a group call: %v", err)
	}
	plain, _ := s.Start(ctx, ada, []string{"bob"}, "video", SFU)
	if _, err := s.JoinGroupCall(ctx, Actor{ID: "cy"}, plain.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("joined a call that is not a group's: %v", err)
	}
	_, _ = s.End(ctx, ada, c.ID)
	if _, ok, _ := s.ActiveGroupCall(ctx, "", "grp_1"); ok {
		t.Fatal("an ended call is still the group's active call")
	}
}

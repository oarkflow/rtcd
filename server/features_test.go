package server_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/client"
	"github.com/oarkflow/rtcd/server"
	"golang.org/x/net/websocket"
)

type grp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Owner   string `json:"owner"`
	Members []struct {
		User string `json:"user"`
		Role string `json:"role"`
	} `json:"members"`
}

func TestUsersMakeAndCallTheirOwnGroups(t *testing.T) {
	s := start(t, nil)
	ada, bob, cy, dan, eve := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "cy"), s.dial(s.acme, "dan"), s.dial(s.acme, "eve")

	var g grp
	ada.must("group.create", map[string]any{"name": "Design team", "members": []string{"bob", "cy"}}, &g)
	if g.Owner != "ada" || len(g.Members) != 3 {
		t.Fatalf("%+v", g)
	}
	bob.next("group.added")
	cy.next("group.added")

	// Members see it; others cannot tell it exists.
	var list struct{ Groups []grp }
	bob.must("group.list", nil, &list)
	if len(list.Groups) != 1 || list.Groups[0].ID != g.ID {
		t.Fatalf("%+v", list)
	}
	if err := eve.call("group.get", map[string]any{"group": g.ID}, nil); code(err) != "forbidden" {
		t.Fatalf("%v", err)
	}
	if err := eve.call("group.call", map[string]any{"group": g.ID}, nil); code(err) != "forbidden" {
		t.Fatalf("a stranger called a group: %v", err)
	}
	// Two members tapping "call" at once land in one call.
	var calls [2]startedGroup
	var wg sync.WaitGroup
	for i, p := range []*peer{ada, bob} {
		wg.Add(1)
		go func(i int, p *peer) {
			defer wg.Done()
			if err := p.call("group.call", map[string]any{"group": g.ID, "mode": "sfu"}, &calls[i]); err != nil {
				t.Errorf("%s: %v", p.user, err)
			}
		}(i, p)
	}
	wg.Wait()
	if calls[0].Call.ID == "" || calls[0].Call.ID != calls[1].Call.ID {
		t.Fatalf("two members started two calls: %s and %s", calls[0].Call.ID, calls[1].Call.ID)
	}
	if calls[0].JoinedExisting == calls[1].JoinedExisting {
		t.Fatalf("exactly one of them starts the call: %+v %+v", calls[0], calls[1])
	}
	id := calls[0].Call.ID
	if calls[0].Call.Group != g.ID {
		t.Fatalf("the call does not know its group: %+v", calls[0].Call)
	}
	cy.next("call.incoming")
	// A member added later joins the group's call; one removed cannot.
	ada.must("group.add", map[string]any{"group": g.ID, "users": []string{"dan"}}, nil)
	dan.next("group.added")
	var joined startedGroup
	dan.must("group.call", map[string]any{"group": g.ID}, &joined)
	if joined.Call.ID != id || !joined.JoinedExisting {
		t.Fatalf("dan did not join the group's call: %+v", joined)
	}
	dan.must("call.answer", map[string]any{"call": id}, nil)
	ada.must("group.remove", map[string]any{"group": g.ID, "users": []string{"dan"}}, nil)
	dan.next("group.removed")
	if err := dan.call("group.call", map[string]any{"group": g.ID}, nil); code(err) != "forbidden" {
		t.Fatalf("a removed member called the group: %v", err)
	}
	// Whoever did not start the call answers it; then a participant invites an outsider.
	for _, p := range []*peer{ada, bob} {
		if p.user != calls[0].Call.Initiator {
			p.must("call.answer", map[string]any{"call": id}, nil)
		}
	}
	initiator := ada
	if calls[0].Call.Initiator == "bob" {
		initiator = bob
	}
	initiator.must("call.invite", map[string]any{"call": id, "users": []string{"eve"}}, nil)
	eve.next("call.incoming")
	// Roles are enforced; deleting ends the group, not the call under way.
	if err := bob.call("group.rename", map[string]any{"group": g.ID, "name": "x"}, nil); code(err) != "forbidden" {
		t.Fatalf("a member renamed the group: %v", err)
	}
	ada.must("group.role", map[string]any{"group": g.ID, "user": "bob", "role": "admin"}, nil)
	bob.must("group.rename", map[string]any{"group": g.ID, "name": "Renamed"}, nil)
	ada.must("group.delete", map[string]any{"group": g.ID}, nil)
	cy.next("group.deleted")
	if err := cy.call("group.get", map[string]any{"group": g.ID}, nil); code(err) != "forbidden" {
		t.Fatalf("%v", err)
	}
	var c client.Call
	ada.must("call.get", map[string]any{"call": id}, &c)
	if c.Status == "ended" {
		t.Fatal("deleting a group ended its call")
	}
}

type startedGroup struct {
	Call           client.Call `json:"call"`
	JoinedExisting bool        `json:"joined_existing"`
}

func TestGroupsAreIsolatedBetweenTenantsAndLimited(t *testing.T) {
	s := start(t, func(c *server.Config) { c.MaxOwnedGroups = 2; c.MaxGroupMembers = 3 })
	a, z := s.dial(s.acme, "ada"), s.dial(s.zeta, "ada")
	var g grp
	a.must("group.create", map[string]any{"name": "acme"}, &g)
	if err := z.call("group.get", map[string]any{"group": g.ID}, nil); code(err) != "forbidden" {
		t.Fatalf("another tenant's ada saw the group: %v", err)
	}
	var list struct{ Groups []grp }
	z.must("group.list", nil, &list)
	if len(list.Groups) != 0 {
		t.Fatalf("%+v", list)
	}
	a.must("group.create", map[string]any{"name": "two"}, nil)
	if err := a.call("group.create", map[string]any{"name": "three"}, nil); code(err) != "limit_reached" {
		t.Fatalf("a third group: %v", err)
	}
	if err := a.call("group.add", map[string]any{"group": g.ID, "users": []string{"b", "c", "d"}}, nil); code(err) != "limit_reached" {
		t.Fatalf("an oversize group: %v", err)
	}
	// The same operations work for a backend over HTTP.
	var out struct{ Groups []grp }
	if err := s.acme.As("ada").Do(bg, "group.list", nil, &out); err != nil || len(out.Groups) != 2 {
		t.Fatalf("%+v %v", out, err)
	}
	var one grp
	if err := s.acme.As("ada").Do(bg, "group.get", map[string]any{"group": g.ID}, &one); err != nil || one.ID != g.ID {
		t.Fatalf("%+v %v", one, err)
	}
}

func TestEverythingIsAuditedAndNothingSecretIsInIt(t *testing.T) {
	s := start(t, nil)
	ada, bob, eve := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "eve")
	var st startReply
	ada.must("call.start", map[string]any{"to": []string{"bob"}, "mode": "sfu"}, &st)
	id := st.Call.ID
	bob.next("call.incoming")
	bob.must("call.answer", map[string]any{"call": id}, nil)
	const secret = "TOP-SECRET-KEY-MATERIAL-0123456789"
	ada.must("call.e2ee", map[string]any{"call": id, "to": "bob", "data": secret}, nil)
	if err := ada.call("call.signal", map[string]any{"call": id, "to": "bob", "type": "offer", "data": map[string]any{"sdp": secret}}, nil); code(err) != "invalid" {
		t.Fatalf("signaling an sfu call: %v", err) // refused, and still audited
	}
	_ = eve.call("call.get", map[string]any{"call": id}, nil)
	_ = eve.call("call.end", map[string]any{"call": id}, nil)
	_ = eve.call("audit.query", map[string]any{}, nil)
	_ = ada.call("ice", nil, nil) // quiet and successful: counted, not logged
	ada.must("call.end", map[string]any{"call": id}, nil)
	if _, err := s.acme.Token(bg, "cy", time.Minute); err != nil {
		t.Fatal(err)
	}
	// A bad credential is audited too, but cannot be tied to a tenant.
	_, _ = client.NewUser(s.base, "garbage-garbage-garbage-garbage").Dial(bg, client.DialOptions{Origin: origin})
	flush(t, s)

	evs, err := s.acme.Audit(bg, client.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	find := func(action, actor, outcome string) *client.AuditEvent {
		for i := range evs {
			if evs[i].Action == action && evs[i].Actor == actor && evs[i].Outcome == outcome {
				return &evs[i]
			}
		}
		return nil
	}
	start := find("call.start", "ada", "ok")
	if start == nil || start.Target != id || start.Transport != "ws" || start.Conn == "" || start.IP != "127.0.0.1" || start.Meta["mode"] != "sfu" {
		t.Fatalf("call.start: %+v", start)
	}
	for _, want := range [][3]string{
		{"ws.open", "ada", "ok"}, {"ws.open", "bob", "ok"}, {"call.answer", "bob", "ok"}, {"call.e2ee", "ada", "ok"},
		{"call.signal", "ada", "error"}, // a p2p-only operation on a group call
		{"call.get", "eve", "denied"}, {"call.end", "eve", "denied"}, {"audit.query", "eve", "denied"}, {"call.end", "ada", "ok"},
	} {
		if find(want[0], want[1], want[2]) == nil {
			t.Errorf("missing %v", want)
		}
	}
	if e := find("call.get", "eve", "denied"); e != nil && (e.Code != "forbidden" || e.Target != id) {
		t.Errorf("the denial does not say why or on what: %+v", e)
	}
	tok := func() *client.AuditEvent {
		for i := range evs {
			if evs[i].Action == "token.mint" && evs[i].Target == "cy" {
				return &evs[i]
			}
		}
		return nil
	}()
	if tok == nil || tok.Service != "chat" || tok.Transport != "http" || tok.Target != "cy" {
		t.Fatalf("token.mint: %+v", tok)
	}
	for _, e := range evs {
		if e.Action == "ice" && e.Outcome == "ok" {
			t.Fatalf("a quiet background operation was logged: %+v", e)
		}
	}
	// What was said is never in the log, only that something was.
	raw, _ := json.Marshal(evs)
	if strings.Contains(string(raw), secret) {
		t.Fatal("message contents are in the audit log")
	}
	if e := find("call.e2ee", "ada", "ok"); e == nil || e.Meta["bytes"] != float64(len(secret)) || e.Meta["to"] != "bob" {
		t.Fatalf("the relay should record who and how big: %+v", e)
	}
	// The chain holds, and the other tenant sees none of it.
	v, err := s.acme.VerifyAudit(bg, 0)
	if err != nil || !v.Verification.OK || int(v.Verification.Checked) < len(evs) || v.HeadHash == "" {
		t.Fatalf("%+v %v (%d events)", v, err, len(evs))
	}
	zeta, _ := s.zeta.Audit(bg, client.AuditFilter{})
	if len(zeta) != 0 {
		t.Fatalf("zeta read %d of acme's entries", len(zeta))
	}
	anon, _ := s.srv.Audit.Query(bg, audit.NoTenant, audit.Filter{Action: "auth.failed"})
	if len(anon) == 0 || anon[0].Code != "unauthenticated" || anon[0].IP != "127.0.0.1" {
		t.Fatalf("a failed login was not audited: %+v", anon)
	}
	// Filters and paging.
	denied, _ := s.acme.Audit(bg, client.AuditFilter{Outcome: "denied"})
	if len(denied) < 3 {
		t.Fatalf("%d denials", len(denied))
	}
	calls, _ := s.acme.Audit(bg, client.AuditFilter{Action: "call."})
	for _, e := range calls {
		if !strings.HasPrefix(e.Action, "call.") {
			t.Fatalf("%s matched call.", e.Action)
		}
	}
	page1, _ := s.acme.Audit(bg, client.AuditFilter{Limit: 3})
	page2, _ := s.acme.Audit(bg, client.AuditFilter{Limit: 3, AfterSeq: page1[2].Seq})
	if len(page1) != 3 || len(page2) != 3 || page2[0].Seq != page1[2].Seq+1 {
		t.Fatalf("paging: %d %d", len(page1), len(page2))
	}
	byTarget, _ := s.acme.Audit(bg, client.AuditFilter{Target: id})
	if len(byTarget) < 6 {
		t.Fatalf("%d entries for the call", len(byTarget))
	}
}

func flush(t *testing.T, s *svc) {
	t.Helper()
	ctx, cancel := contextTimeout(10 * time.Second)
	defer cancel()
	if err := s.srv.Audit.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAConnectionIsAuditedFromOpenToClose(t *testing.T) {
	s := start(t, nil)
	p := s.dial(s.acme, "ada")
	p.Close()
	deadline := time.Now().Add(5 * time.Second)
	var evs []client.AuditEvent
	for time.Now().Before(deadline) {
		flush(t, s)
		evs, _ = s.acme.Audit(bg, client.AuditFilter{Action: "ws."})
		if len(evs) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(evs) < 2 || evs[0].Action != "ws.open" || evs[len(evs)-1].Action != "ws.close" || evs[0].Conn != evs[len(evs)-1].Conn {
		t.Fatalf("%+v", evs)
	}
}

func TestFloodingAPersonDoesNotDropThemOrSlowOthers(t *testing.T) {
	s := start(t, nil) // default limits: 100 messages a second per call, burst 200
	ada, bob, cy := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "cy")
	var st startReply
	ada.must("call.start", map[string]any{"to": []string{"bob"}, "mode": "sfu"}, &st)
	bob.next("call.incoming")
	bob.must("call.answer", map[string]any{"call": st.Call.ID}, nil)

	var ok, limited atomic.Int64
	for i := 0; i < 1000; i++ {
		err := ada.call("call.e2ee", map[string]any{"call": st.Call.ID, "to": "bob", "data": "k"}, nil)
		switch code(err) {
		case "":
			ok.Add(1)
		case "rate_limited":
			limited.Add(1)
		default:
			t.Fatalf("%v", err)
		}
	}
	if limited.Load() == 0 || ok.Load() > 400 {
		t.Fatalf("a burst of 1000 messages: %d went through, %d were limited", ok.Load(), limited.Load())
	}
	// The one flooded was not disconnected for it, and still hears what was let through.
	bob.next("call.e2ee")
	if err := bob.call("ice", nil, nil); err != nil {
		t.Fatalf("the person flooded was cut off: %v", err)
	}
	// Somebody unrelated is untouched.
	start := time.Now()
	if err := cy.call("ice", nil, nil); err != nil || time.Since(start) > time.Second {
		t.Fatalf("an unrelated user was slowed: %v %v", err, time.Since(start))
	}
	flush(t, s)
	lim, _ := s.acme.Audit(bg, client.AuditFilter{Outcome: "denied", Action: "call.e2ee"})
	if len(lim) == 0 || lim[0].Code != "rate_limited" {
		t.Fatalf("the refusals were not audited: %+v", lim)
	}
}

func TestASlowReaderIsDroppedAndNobodyElseNoticesIt(t *testing.T) {
	s := start(t, func(c *server.Config) {
		c.WriterQueue = 8
		c.RelayPerSecond, c.RelayBurst = 1e6, 1e6
		c.OpsPerSecond, c.OpsBurst = 1e6, 1e6
	})
	ada, cy := s.dial(s.acme, "ada"), s.dial(s.acme, "cy")
	var st startReply
	ada.must("call.start", map[string]any{"to": []string{"slow", "cy"}, "mode": "sfu"}, &st)
	cy.next("call.incoming")
	// "slow" connects and then never reads.
	tok, _ := s.acme.Token(bg, "slow", time.Minute)
	slow := dialRaw(t, s.base, tok.Token)
	defer slow.Close()
	var sc startReply
	_ = sc
	slowUser := client.NewUser(s.base, tok.Token)
	_ = slowUser
	// slow answers over HTTP so it is part of the call.
	if _, err := s.acme.As("slow").Answer(bg, st.Call.ID); err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("a", 15<<10)
	var senderWorst, otherWorst time.Duration
	sent := 0
	deadline := time.Now().Add(60 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		t0 := time.Now()
		if err := ada.call("call.e2ee", map[string]any{"call": st.Call.ID, "to": "slow", "data": payload}, nil); err != nil {
			t.Fatalf("the sender was affected by a slow receiver: %v", err)
		}
		if d := time.Since(t0); d > senderWorst {
			senderWorst = d
		}
		sent++
		if i%5 == 0 {
			t1 := time.Now()
			if err := cy.call("ice", nil, nil); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(t1); d > otherWorst {
				otherWorst = d
			}
		}
		if s.srv.Stats().SlowClientsDisconnected > 0 {
			break
		}
	}
	if s.srv.Stats().SlowClientsDisconnected == 0 {
		t.Fatal("a connection that never reads was never dropped")
	}
	// Feeding a reader that has stopped must cost the sender and everyone else nothing.
	if senderWorst > 250*time.Millisecond || otherWorst > 250*time.Millisecond {
		t.Fatalf("a slow reader slowed others: the sender waited up to %v, an unrelated user up to %v", senderWorst, otherWorst)
	}
	flush(t, s)
	evs, _ := s.acme.Audit(bg, client.AuditFilter{Action: "ws.slow_client"})
	if len(evs) != 1 || evs[0].Actor != "slow" {
		t.Fatalf("the drop was not audited exactly once: %+v", evs)
	}
	t.Logf("after %d messages a slow reader was dropped; the sender's worst wait was %v, an unrelated user's %v", sent, senderWorst, otherWorst)
}

func dialRaw(t *testing.T, base, token string) *websocket.Conn {
	t.Helper()
	cfg, err := websocket.NewConfig("ws"+strings.TrimPrefix(base, "http")+"/v1/ws?token="+token, origin)
	if err != nil {
		t.Fatal(err)
	}
	c, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestManyUsersCallAtOnceWithoutInterference(t *testing.T) {
	s := start(t, func(c *server.Config) { c.OpsPerSecond, c.OpsBurst = 1e6, 1e6 })
	const pairs = 40
	var wg sync.WaitGroup
	errs := make(chan error, pairs*2)
	for i := 0; i < pairs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, b := fmt.Sprintf("a%d", i), fmt.Sprintf("b%d", i)
			ac, bc := s.dial(s.acme, a), s.dial(s.acme, b)
			var st startReply
			if err := ac.call("call.start", map[string]any{"to": []string{b}}, &st); err != nil {
				errs <- err
				return
			}
			bc.next("call.incoming")
			if err := bc.call("call.answer", map[string]any{"call": st.Call.ID}, nil); err != nil {
				errs <- err
				return
			}
			for j := 0; j < 20; j++ {
				if err := ac.call("call.e2ee", map[string]any{"call": st.Call.ID, "to": b, "data": fmt.Sprint(i, "-", j)}, nil); err != nil {
					errs <- err
					return
				}
				ev := bc.next("call.e2ee")
				if field(ev.Data, "data") != fmt.Sprint(i, "-", j) || field(ev.Data, "from") != a {
					errs <- fmt.Errorf("pair %d heard %s", i, ev.Data)
					return
				}
			}
			_ = ac.call("call.end", map[string]any{"call": st.Call.ID}, nil)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

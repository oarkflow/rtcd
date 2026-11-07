package server_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/oarkflow/rtcd/client"
)

func mb64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

type claimed struct {
	User, Device, KP string
	LastResort       bool `json:"last_resort"`
}

// publishKPs gives a user a device with a few packages and a last-resort one.
func publishKPs(t *testing.T, p *peer, device string) {
	t.Helper()
	var out struct{ Added int }
	p.must("mls.kp.put", map[string]any{"device": device, "kps": []map[string]any{
		{"kp": mb64(p.user + "-" + device + "-1")}, {"kp": mb64(p.user + "-" + device + "-2")},
		{"kp": mb64(p.user + "-" + device + "-last"), "last_resort": true}}}, &out)
	if out.Added != 3 {
		t.Fatalf("%s published %d", p.user, out.Added)
	}
}

func TestMLSGroupLifecycleOverTheWire(t *testing.T) {
	s := start(t, nil)
	ada, bob, cy, eve := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "cy"), s.dial(s.acme, "eve")
	publishKPs(t, bob, "phone")
	publishKPs(t, cy, "phone")
	g := group(t, ada, "bob", "cy")

	// The creator binds the conversation to a group at epoch 0.
	var made struct {
		GroupID string `json:"group_id"`
		Suite   int
		Epoch   int64
	}
	ada.must("mls.group.create", map[string]any{"conv": g, "group_id": mb64("gid"), "suite": 1}, &made)
	if made.Epoch != 0 || made.Suite != 1 {
		t.Fatalf("created: %+v", made)
	}
	if code(eve.call("mls.group.get", map[string]any{"conv": g}, nil)) != "forbidden" {
		t.Fatal("a stranger read a group")
	}

	// A stranger cannot use up someone's packages, and nobody can claim for a person outside the roster.
	if code(eve.call("mls.kp.claim", map[string]any{"conv": g, "users": []string{"bob"}}, nil)) != "forbidden" {
		t.Fatal("a stranger claimed key packages")
	}
	if err := ada.call("mls.kp.claim", map[string]any{"conv": g, "users": []string{"eve"}}, nil); code(err) != "invalid" {
		t.Fatalf("claim for a non-member: %v", err)
	}

	// Ada adds bob and cy in one claim and one commit.
	var cl struct {
		KeyPackages []claimed `json:"key_packages"`
		Missing     []string
	}
	ada.must("mls.kp.claim", map[string]any{"conv": g, "users": []string{"bob", "cy"}}, &cl)
	if len(cl.KeyPackages) != 2 || len(cl.Missing) != 0 {
		t.Fatalf("claim: %+v", cl)
	}
	var out struct {
		Epoch, Seq int64
	}
	ada.must("mls.commit", map[string]any{"conv": g, "device": "d1", "epoch": 1, "id": "c1", "body": mb64("commit-1"), "group_info": mb64("gi-1"),
		"welcomes": []map[string]any{{"user": "bob", "device": "phone", "w": mb64("w-bob")}, {"user": "cy", "device": "phone", "w": mb64("w-cy")}}}, &out)
	if out.Epoch != 1 || out.Seq != 1 {
		t.Fatalf("commit: %+v", out)
	}

	// Members hear of the commit with its body inside, and the added people hear of their welcome.
	ev := bob.next("mls.commit")
	if field(ev.Data, "epoch") != float64(1) || field(ev.Data, "body") != mb64("commit-1") || field(ev.Data, "by") != "ada" {
		t.Fatalf("event: %s", ev.Data)
	}
	bob.next("mls.welcome")
	cy.next("mls.welcome")

	// Bob reads his welcome, and cy's is not in it.
	var sync struct {
		Messages []struct {
			Seq        int64
			Kind, Body string
			Epoch      int64
		}
		Epoch int64
	}
	var raw json.RawMessage
	bob.must("mls.sync", map[string]any{"conv": g, "device": "phone", "after": 0}, &raw)
	if err := json.Unmarshal(raw, &sync); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, m := range sync.Messages {
		kinds = append(kinds, m.Kind)
		if m.Kind == "welcome" && m.Body != mb64("w-bob") {
			t.Fatalf("bob was handed %q", m.Body)
		}
	}
	if fmt.Sprint(kinds) != "[commit welcome]" || sync.Epoch != 1 {
		t.Fatalf("sync: %v epoch %d", kinds, sync.Epoch)
	}
	var gi struct {
		GroupInfo string `json:"group_info"`
		Epoch     int64
	}
	bob.must("mls.group.get", map[string]any{"conv": g}, &gi)
	if gi.GroupInfo != mb64("gi-1") || gi.Epoch != 1 {
		t.Fatalf("group info: %+v", gi)
	}

	// Application messages ride the ordinary send, sealed under the group's epoch.
	var sent struct{ Seq int64 }
	bob.must("msg.send", map[string]any{"conv": g, "id": "m1", "body": "mls-ciphertext", "epoch": 1}, &sent)
	if sent.Seq != 1 {
		t.Fatalf("send: %+v", sent)
	}
	cy.next("msg.new")
	if err := bob.call("msg.send", map[string]any{"conv": g, "id": "m2", "body": "x", "epoch": 7}, nil); code(err) != "stale_epoch" {
		t.Fatalf("a message from another epoch: %v", err)
	}

	// Two members commit at once: one wins, the other is told the epoch and rebuilds.
	errs := make(chan error, 2)
	for i, p := range []*peer{ada, bob} {
		go func(i int, p *peer) {
			errs <- p.call("mls.commit", map[string]any{"conv": g, "device": fmt.Sprint("d", i), "epoch": 2, "id": fmt.Sprint("race", i), "body": mb64(fmt.Sprint("r", i))}, nil)
		}(i, p)
	}
	e1, e2 := <-errs, <-errs
	if (e1 == nil) == (e2 == nil) {
		t.Fatalf("exactly one commit should win: %v / %v", e1, e2)
	}
	loser := e1
	if loser == nil {
		loser = e2
	}
	var ce *client.Error
	if !errors.As(loser, &ce) || ce.Code != "mls_epoch_conflict" || ce.Message != "current_epoch=2" || ce.Status != 409 {
		t.Fatalf("the loser: %v", loser)
	}

	// The old scheme cannot move an MLS group's epoch.
	if err := ada.call("epoch.rotate", map[string]any{"conv": g, "device": "d1", "epoch": 3, "wraps": []any{}}, nil); err == nil {
		t.Fatal("epoch.rotate moved an MLS group")
	}

	// Taking cy out of the roster fences the group: no application message until a commit removes cy.
	ada.must("group.remove", map[string]any{"group": g, "users": []string{"cy"}}, nil)
	time.Sleep(50 * time.Millisecond)
	if err := bob.call("msg.send", map[string]any{"conv": g, "id": "m3", "body": "x", "epoch": 2}, nil); code(err) != "rekey_required" {
		t.Fatalf("a send while a removed member still holds the keys: %v", err)
	}
	var grp struct {
		Rekey   bool     `json:"rekey_required"`
		Pending []string `json:"pending_removals"`
	}
	bob.must("mls.group.get", map[string]any{"conv": g}, &grp)
	if !grp.Rekey || fmt.Sprint(grp.Pending) != "[cy]" {
		t.Fatalf("group: %+v", grp)
	}
	if err := cy.call("mls.sync", map[string]any{"conv": g, "device": "phone", "after": 0}, nil); code(err) != "forbidden" {
		t.Fatalf("a removed member can still read handshakes: %v", err)
	}
	bob.must("mls.commit", map[string]any{"conv": g, "device": "phone", "epoch": 3, "id": "rm", "body": mb64("remove-cy"), "removed": []string{"cy"}}, nil)
	bob.must("msg.send", map[string]any{"conv": g, "id": "m4", "body": "x", "epoch": 3}, nil)
}

func TestAConversationOfTheOlderSchemeCannotBecomeMLS(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	g := group(t, ada, "bob")
	_ = bob
	ada.must("key.publish", map[string]any{"device": "d1", "pub": "pubkey"}, nil)
	bob.must("key.publish", map[string]any{"device": "d1", "pub": "pubkey2"}, nil)
	ada.must("epoch.rotate", map[string]any{"conv": g, "device": "d1", "epoch": 1, "wraps": []map[string]any{{"user": "ada", "device": "d1", "w": "w1"}, {"user": "bob", "device": "d1", "w": "w2"}}}, nil)
	if err := ada.call("mls.group.create", map[string]any{"conv": g, "group_id": mb64("g"), "suite": 1}, nil); code(err) != "conflict" {
		t.Fatalf("expected a conflict: %v", err)
	}
}

func TestAnMLSGroupNobodyWasAddedToTakesNoMessages(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	g := group(t, ada, "bob")
	_ = bob
	ada.must("mls.group.create", map[string]any{"conv": g, "group_id": mb64("g0"), "suite": 1}, nil)
	if err := ada.call("msg.send", map[string]any{"conv": g, "id": "m", "body": "x", "epoch": 0}, nil); code(err) != "rekey_required" {
		t.Fatalf("a message only its sender could read was accepted: %v", err)
	}
}

func TestClaimingOnePersonsPackagesIsLimited(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	publishKPs(t, bob, "phone")
	g := group(t, ada, "bob")
	var limited int
	for i := 0; i < 12; i++ {
		if err := ada.call("mls.kp.claim", map[string]any{"conv": g, "users": []string{"bob"}}, nil); code(err) == "rate_limited" {
			limited++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if limited == 0 {
		t.Fatal("a member drained another's key packages without limit")
	}
}

func TestALargeCommitGoesOverRESTAndASmallOneOverTheSocket(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	g := group(t, ada, "bob")
	ada.must("mls.group.create", map[string]any{"conv": g, "group_id": mb64("gbig"), "suite": 1}, nil)
	post := func(tok, path string, v any) (int, []byte) {
		b, _ := json.Marshal(v)
		return s.api(tok, "POST", path, b, nil)
	}
	// A small commit rides the socket.
	ada.must("mls.commit", map[string]any{"conv": g, "device": "d1", "epoch": 1, "id": "small", "body": mb64("c")}, nil)
	// ~930 KiB of GroupInfo (a ratchet tree for a big group) goes over REST.
	big := make([]byte, 700<<10)
	for i := range big {
		big[i] = byte(i * 7)
	}
	tok := s.token("ada")
	if st, b := post(tok, "/v1/mls/commit", map[string]any{"conv": g, "device": "d1", "epoch": 2, "id": "big", "body": mb64("c"), "group_info": mb64(string(big)),
		"welcomes": []map[string]any{{"user": "bob", "device": "d", "w": mb64("w")}}}); st != 200 {
		t.Fatalf("large commit over REST: %d %.200s", st, b)
	}
	var ws struct {
		Omitted bool  `json:"group_info_omitted"`
		Bytes   int   `json:"group_info_bytes"`
		Epoch   int64 `json:"epoch"`
	}
	bob.must("mls.group.get", map[string]any{"conv": g}, &ws)
	if !ws.Omitted || ws.Bytes < 900<<10 || ws.Epoch != 2 {
		t.Fatalf("over the socket the group info is reported, not sent: %+v", ws)
	}
	var gi struct {
		GroupInfo string `json:"group_info"`
	}
	st, rb := post(s.token("bob"), "/v1/mls/group/get", map[string]any{"conv": g})
	if st != 200 || json.Unmarshal(rb, &gi) != nil {
		t.Fatalf("group get over REST: %d %.200s", st, rb)
	}
	if len(gi.GroupInfo) < 900<<10 {
		t.Fatalf("group info came back as %d bytes", len(gi.GroupInfo))
	}
	// Over the operation's own limit: refused with a reason.
	tooBig := mb64(string(make([]byte, 2<<20)))
	if st, b := post(tok, "/v1/mls/commit", map[string]any{"conv": g, "device": "d1", "epoch": 3, "id": "huge", "body": tooBig}); st != 413 {
		t.Fatalf("oversized commit: %d %.200s", st, b)
	}
}

func TestMLSOperationsAreReachableOverREST(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	g := group(t, ada, "bob")
	_ = bob
	tok := s.token("ada")
	post := func(path string, v any) (int, []byte) {
		b, _ := json.Marshal(v)
		return s.api(tok, "POST", path, b, nil)
	}
	if st, b := post("/v1/mls/group/create", map[string]any{"conv": g, "group_id": mb64("rest"), "suite": 1}); st != 200 {
		t.Fatalf("create: %d %s", st, b)
	}
	if st, b := post("/v1/mls/commit", map[string]any{"conv": g, "device": "d1", "epoch": 1, "id": "k", "body": mb64("c")}); st != 200 {
		t.Fatalf("commit: %d %s", st, b)
	}
	st, b := post("/v1/mls/commit", map[string]any{"conv": g, "device": "d2", "epoch": 1, "id": "k2", "body": mb64("c2")})
	if st != 409 || field(b, "error", "code") != "mls_epoch_conflict" && field(b, "code") != "mls_epoch_conflict" {
		t.Fatalf("a lost race over REST: %d %s", st, b)
	}
	if st, b := post("/v1/mls/sync", map[string]any{"conv": g, "device": "d1", "after": 0}); st != 200 || field(b, "epoch") != float64(1) {
		t.Fatalf("sync: %d %s", st, b)
	}
}

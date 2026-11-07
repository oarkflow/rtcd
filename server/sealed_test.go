package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func tokenFor(seed string) (token, verifier string) {
	t := sha256.Sum256([]byte("token:" + seed))
	v := sha256.Sum256(t[:])
	return base64.RawURLEncoding.EncodeToString(t[:]), hex.EncodeToString(v[:])
}

// sealedGroup makes an MLS group of ada and bob at epoch 1 with seed "e1"'s token.
func sealedGroup(t *testing.T, s *svc) (conv string, ada, bob *peer) {
	t.Helper()
	ada, bob = s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	conv = group(t, ada, "bob")
	ada.must("mls.group.create", map[string]any{"conv": conv, "group_id": mb64("sealed-" + conv), "suite": 1}, nil)
	_, v := tokenFor("e1")
	ada.must("mls.commit", map[string]any{"conv": conv, "device": "d1", "epoch": 1, "id": "c1", "body": mb64("c1"), "sealed_verifier": v}, nil)
	return
}

func (s *svc) sealed(body map[string]any) (int, []byte) {
	b, _ := json.Marshal(body)
	return s.api("", "POST", "/v1/sealed/send", b, nil)
}

func TestAMemberSendsWithoutSigningInAndTheServiceStoresNoSender(t *testing.T) {
	s := start(t, nil)
	conv, _, bob := sealedGroup(t, s)
	tok, _ := tokenFor("e1")

	st, b := s.sealed(map[string]any{"tenant": "acme", "conv": conv, "id": "m1", "body": "mls-ciphertext", "epoch": 1, "token": tok})
	if st != 200 || field(b, "seq") != float64(1) {
		t.Fatalf("sealed send: %d %s", st, b)
	}
	ev := bob.next("msg.new")
	if field(ev.Data, "sender") != "~sealed" || ev.From != "" || field(ev.Data, "body") != "mls-ciphertext" {
		t.Fatalf("the event names a sender: from=%q %s", ev.From, ev.Data)
	}
	hist, _ := json.Marshal(map[string]any{"conv": conv, "after": 0})
	_, h := s.api(s.token("bob"), "POST", "/v1/msg/history", hist, nil)
	var out struct {
		Messages []struct{ Sender string }
	}
	_ = json.Unmarshal(h, &out)
	if len(out.Messages) != 1 || out.Messages[0].Sender != "~sealed" {
		t.Fatalf("history: %s", h)
	}
	// A retry is recognised, not stored twice.
	st, b = s.sealed(map[string]any{"tenant": "acme", "conv": conv, "id": "m1", "body": "mls-ciphertext", "epoch": 1, "token": tok})
	if st != 200 || field(b, "duplicate") != true {
		t.Fatalf("retry: %d %s", st, b)
	}
}

func TestEveryWayToBeRefusedLooksTheSame(t *testing.T) {
	s := start(t, nil)
	conv, _, _ := sealedGroup(t, s)
	good, _ := tokenFor("e1")
	wrong, _ := tokenFor("not-the-token")
	cases := map[string]map[string]any{
		"wrong token":    {"tenant": "acme", "conv": conv, "id": "a", "body": "x", "epoch": 1, "token": wrong},
		"no such conv":   {"tenant": "acme", "conv": "nope", "id": "a", "body": "x", "epoch": 1, "token": good},
		"no such tenant": {"tenant": "other", "conv": conv, "id": "a", "body": "x", "epoch": 1, "token": good},
		"wrong epoch":    {"tenant": "acme", "conv": conv, "id": "a", "body": "x", "epoch": 9, "token": good},
		"short token":    {"tenant": "acme", "conv": conv, "id": "a", "body": "x", "epoch": 1, "token": "AAAA"},
		"a future epoch": {"tenant": "acme", "conv": conv, "id": "a", "body": "x", "epoch": 2, "token": good},
		"missing id":     {"tenant": "acme", "conv": conv, "body": "x", "epoch": 1, "token": good},
	}
	var want string
	for name, body := range cases {
		st, b := s.sealed(body)
		if st != 403 {
			t.Fatalf("%s: %d %s", name, st, b)
		}
		if want == "" {
			want = string(b)
		} else if string(b) != want {
			t.Fatalf("%s answered differently, which tells a prober something:\n%s\nvs\n%s", name, b, want)
		}
	}
	// A conversation that is not MLS at all gives the same answer.
	ada := s.dial(s.acme, "ada")
	other := group(t, ada, "bob")
	if st, b := s.sealed(map[string]any{"tenant": "acme", "conv": other, "id": "a", "body": "x", "epoch": 0, "token": good}); st != 403 || string(b) != want {
		t.Fatalf("a non-MLS conversation: %d %s", st, b)
	}
}

func TestTheTokenChangesWithTheEpochSoARemovedMemberLosesIt(t *testing.T) {
	s := start(t, nil)
	conv, ada, _ := sealedGroup(t, s)
	t1, _ := tokenFor("e1")
	t2, v2 := tokenFor("e2")
	t3, v3 := tokenFor("e3")
	send := func(tok string, epoch int, id string) int {
		st, _ := s.sealed(map[string]any{"tenant": "acme", "conv": conv, "id": id, "body": "x", "epoch": epoch, "token": tok})
		return st
	}
	if send(t1, 1, "a") != 200 {
		t.Fatal("epoch 1 token at epoch 1")
	}
	ada.must("mls.commit", map[string]any{"conv": conv, "device": "d1", "epoch": 2, "id": "c2", "body": mb64("c2"), "sealed_verifier": v2}, nil)
	if send(t2, 2, "b") != 200 {
		t.Fatal("new epoch's token")
	}
	if send(t1, 1, "c") != 200 {
		t.Fatal("the previous epoch is still accepted, as for msg.send")
	}
	if send(t1, 2, "d") != 403 {
		t.Fatal("an old token must not open a new epoch")
	}
	ada.must("mls.commit", map[string]any{"conv": conv, "device": "d1", "epoch": 3, "id": "c3", "body": mb64("c3"), "sealed_verifier": v3}, nil)
	if send(t1, 1, "e") != 403 {
		t.Fatal("epoch 1's token must be dead two epochs later")
	}
	if send(t3, 3, "f") != 200 || send(t2, 2, "g") != 200 {
		t.Fatal("current and previous tokens work")
	}
}

func TestAMemberCanSetTheVerifierAfterTheFactForTheCurrentEpochOnly(t *testing.T) {
	s := start(t, nil)
	conv, ada, bob := sealedGroup(t, s)
	_, v2 := tokenFor("e2")
	ada.must("mls.commit", map[string]any{"conv": conv, "device": "d1", "epoch": 2, "id": "c2", "body": mb64("c2")}, nil) // no verifier yet
	t2, _ := tokenFor("e2")
	if st, _ := s.sealed(map[string]any{"tenant": "acme", "conv": conv, "id": "x", "body": "x", "epoch": 2, "token": t2}); st != 403 {
		t.Fatal("no verifier yet, so nothing is accepted")
	}
	// Any member sets it once they have the epoch.
	bob.must("mls.sealed.set", map[string]any{"conv": conv, "epoch": 2, "verifier": v2}, nil)
	if st, b := s.sealed(map[string]any{"tenant": "acme", "conv": conv, "id": "x", "body": "x", "epoch": 2, "token": t2}); st != 200 {
		t.Fatalf("after the verifier is set: %d %s", st, b)
	}
	if err := bob.call("mls.sealed.set", map[string]any{"conv": conv, "epoch": 1, "verifier": v2}, nil); code(err) != "mls_epoch_conflict" {
		t.Fatalf("a verifier for a past epoch: %v", err)
	}
	if err := bob.call("mls.sealed.set", map[string]any{"conv": conv, "epoch": 2, "verifier": "nothex"}, nil); code(err) != "invalid" {
		t.Fatalf("a malformed verifier: %v", err)
	}
	eve := s.dial(s.acme, "eve")
	if err := eve.call("mls.sealed.set", map[string]any{"conv": conv, "epoch": 2, "verifier": v2}, nil); code(err) != "forbidden" {
		t.Fatalf("a stranger set a verifier: %v", err)
	}
}

func TestSealedSendHonoursTheRemovalFence(t *testing.T) {
	s := start(t, nil)
	conv, ada, _ := sealedGroup(t, s)
	ada.dialRemove(t, conv, "bob")
	time.Sleep(60 * time.Millisecond)
	tok, _ := tokenFor("e1")
	st, b := s.sealed(map[string]any{"tenant": "acme", "conv": conv, "id": "m", "body": "x", "epoch": 1, "token": tok})
	if st != 409 || field(b, "error", "code") != "rekey_required" {
		t.Fatalf("a removed member still holds the keys, so no sealed message: %d %s", st, b)
	}
}

func (p *peer) dialRemove(t *testing.T, conv, user string) {
	t.Helper()
	p.must("group.remove", map[string]any{"group": conv, "users": []string{user}}, nil)
}

func TestTheOpenEndpointIsRateLimitedPerAddressAndSizeLimited(t *testing.T) {
	s := start(t, nil)
	conv, _, _ := sealedGroup(t, s)
	tok, _ := tokenFor("e1")
	limited := 0
	for i := 0; i < 150; i++ {
		st, _ := s.sealed(map[string]any{"tenant": "acme", "conv": conv, "id": fmt.Sprint("r", i), "body": "x", "epoch": 1, "token": tok})
		if st == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("one address sent 150 messages without being slowed")
	}
	big := make([]byte, 200<<10)
	st, _ := s.api("", "POST", "/v1/sealed/send", append([]byte(`{"body":"`), append(big, '"', '}')...), nil)
	if st != 413 && st != 429 {
		t.Fatalf("oversized: %d", st)
	}
}

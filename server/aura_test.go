package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/client"
	"github.com/oarkflow/rtcd/server"
)

type wrap struct {
	User   string `json:"user"`
	Device string `json:"device"`
	W      string `json:"w"`
}

// publish gives a user one device with a made-up public key.
func publish(p *peer, device string) {
	p.t.Helper()
	p.must("key.publish", map[string]any{"device": device, "pub": "pub-" + p.user + "-" + device, "cert": "cert-" + device}, nil)
}

func ws(user string, devices ...string) []wrap {
	out := make([]wrap, len(devices))
	for i, d := range devices {
		out[i] = wrap{user, d, "wrapped-for-" + user + "-" + d}
	}
	return out
}

func TestManagedConversationsAreTheBackendsToControl(t *testing.T) {
	s := start(t, nil)
	if _, err := s.acme.OpenConv(bg, client.ConvSpec{ID: "grp_forged", Members: []string{"ada"}}); code(err) != "invalid" {
		t.Fatalf("an id that looks like a user's group: %v", err)
	}
	ada, bob, eve := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "eve")
	r, err := s.acme.OpenConv(bg, client.ConvSpec{ID: "c-1", Members: []string{"ada", "bob"}, Admins: []string{"ada"}})
	if err != nil || !r.Created || len(r.Added) != 2 {
		t.Fatalf("open: %+v %v", r, err)
	}
	ada.next("conv.added")

	var sent struct{ Seq int64 }
	ada.must("msg.send", map[string]any{"conv": "c-1", "id": "a", "body": "x"}, &sent)
	bob.next("msg.new")

	// The people in it can neither see nor change it as a group.
	if err := ada.call("group.get", map[string]any{"group": "c-1"}, nil); code(err) != "forbidden" {
		t.Fatalf("group.get on a managed conversation: %v", err)
	}
	if err := ada.call("group.add", map[string]any{"group": "c-1", "users": []string{"eve"}}, nil); code(err) != "forbidden" {
		t.Fatalf("group.add on a managed conversation: %v", err)
	}
	if err := ada.call("group.delete", map[string]any{"group": "c-1"}, nil); code(err) != "forbidden" {
		t.Fatalf("group.delete on a managed conversation: %v", err)
	}
	var l struct{ Groups []any }
	ada.must("group.list", nil, &l)
	if len(l.Groups) != 0 {
		t.Fatalf("a managed conversation is listed as a group: %+v", l)
	}
	if err := ada.call("conv.open", map[string]any{"id": "c-2"}, nil); code(err) != "service_key_required" {
		t.Fatalf("a user opened a conversation: %v", err)
	}
	if err := eve.call("msg.send", map[string]any{"conv": "c-1", "id": "e", "body": "x"}, nil); code(err) != "forbidden" {
		t.Fatalf("a stranger sent: %v", err)
	}

	// The admin role the backend gave counts for deleting others' messages.
	bob.must("msg.send", map[string]any{"conv": "c-1", "id": "b", "body": "x"}, &sent)
	ada.must("msg.delete", map[string]any{"conv": "c-1", "seq": sent.Seq}, nil)
	if err := bob.call("msg.delete", map[string]any{"conv": "c-1", "seq": 1}, nil); code(err) != "forbidden" {
		t.Fatalf("a member deleted someone else's: %v", err)
	}

	// Another tenant cannot take the id, or learn it is in use by anything but "taken".
	if _, err := s.zeta.OpenConv(bg, client.ConvSpec{ID: "c-1", Members: []string{"zed"}}); code(err) != "id_taken" {
		t.Fatalf("zeta opened acme's id: %v", err)
	}

	// Admission and role.
	if _, err := s.acme.AdmitToConv(bg, "c-1", []string{"eve"}, nil); err != nil {
		t.Fatal(err)
	}
	eve.next("conv.added")
	bob.next("conv.members")
	eve.must("msg.send", map[string]any{"conv": "c-1", "id": "e", "body": "x"}, nil)
	if err := s.acme.SetConvRole(bg, "c-1", "eve", "admin"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.acme.GetConv(bg, "c-1")
	if len(got.Members) != 3 {
		t.Fatalf("members: %+v", got)
	}

	// Removal is immediate and tells the person.
	if _, err := s.acme.RemoveFromConv(bg, "c-1", "eve"); err != nil {
		t.Fatal(err)
	}
	eve.next("conv.removed")
	if err := eve.call("msg.send", map[string]any{"conv": "c-1", "id": "late", "body": "x"}, nil); code(err) != "forbidden" {
		t.Fatalf("a removed member sent: %v", err)
	}
	if err := eve.call("msg.history", map[string]any{"conv": "c-1"}, nil); code(err) != "forbidden" {
		t.Fatalf("a removed member read: %v", err)
	}

	// Closing deletes everything.
	if err := s.acme.CloseConv(bg, "c-1"); err != nil {
		t.Fatal(err)
	}
	bob.next("conv.closed")
	if err := bob.call("msg.history", map[string]any{"conv": "c-1"}, nil); code(err) != "forbidden" {
		t.Fatalf("history of a closed conversation: %v", err)
	}
	if _, err := s.acme.OpenConv(bg, client.ConvSpec{ID: "c-1", Members: []string{"ada"}}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	ada2 := s.dial(s.acme, "ada")
	var h struct{ Messages []any }
	ada2.must("msg.history", map[string]any{"conv": "c-1"}, &h)
	if len(h.Messages) != 0 {
		t.Fatalf("a closed conversation kept its messages: %+v", h)
	}
}

func TestDeviceKeysAreImmutableAndRevocationIsFinal(t *testing.T) {
	s := start(t, func(c *server.Config) { c.MaxDevices = 2 })
	ada := s.dial(s.acme, "ada")
	publish(ada, "phone")
	publish(ada, "phone") // the same key again is fine
	if err := ada.call("key.publish", map[string]any{"device": "phone", "pub": "another"}, nil); code(err) != "conflict" {
		t.Fatalf("a device's key changed: %v", err)
	}
	publish(ada, "laptop")
	if err := ada.call("key.publish", map[string]any{"device": "tablet", "pub": "p"}, nil); code(err) != "limit_reached" {
		t.Fatalf("a third device: %v", err)
	}
	if err := ada.call("key.publish", map[string]any{"device": "bad device!", "pub": "p"}, nil); code(err) != "invalid" {
		t.Fatalf("a bad device id: %v", err)
	}
	// The backend retires the laptop; it cannot come back, and it frees a slot.
	if err := s.acme.RevokeDevice(bg, "ada", "laptop"); err != nil {
		t.Fatal(err)
	}
	if err := ada.call("key.publish", map[string]any{"device": "laptop", "pub": "pub-ada-laptop"}, nil); code(err) != "device_revoked" {
		t.Fatalf("a revoked device published: %v", err)
	}
	publish(ada, "tablet")
	// A device that never published can be revoked ahead of time.
	if err := s.acme.RevokeDevice(bg, "ada", "stolen"); err != nil {
		t.Fatal(err)
	}
	if err := ada.call("key.publish", map[string]any{"device": "stolen", "pub": "p"}, nil); code(err) != "device_revoked" {
		t.Fatalf("a pre-revoked device published: %v", err)
	}

	// The directory is per conversation, members only, active devices only.
	g := group(t, ada, "bob")
	bob, eve := s.dial(s.acme, "bob"), s.dial(s.acme, "eve")
	publish(bob, "b1")
	var l struct {
		Devices []struct{ User, Device, Pub, Cert string }
	}
	bob.must("key.list", map[string]any{"conv": g}, &l)
	if len(l.Devices) != 3 { // ada: phone, tablet; bob: b1
		t.Fatalf("directory: %+v", l)
	}
	for _, d := range l.Devices {
		if d.Device == "laptop" || d.Cert == "" {
			t.Fatalf("directory entry: %+v", d)
		}
	}
	if err := eve.call("key.list", map[string]any{"conv": g}, nil); code(err) != "forbidden" {
		t.Fatalf("a stranger read the directory: %v", err)
	}
}

func TestEpochsKeepARemovedMemberOutOfFutureMessages(t *testing.T) {
	s := start(t, nil)
	if _, err := s.acme.OpenConv(bg, client.ConvSpec{ID: "c", Members: []string{"ada", "bob", "cy"}}); err != nil {
		t.Fatal(err)
	}
	ada, bob, cy := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "cy")
	publish(ada, "a1")
	publish(bob, "b1")
	rotate := func(p *peer, dev string, epoch int64, w ...wrap) error {
		return p.call("epoch.rotate", map[string]any{"conv": "c", "device": dev, "epoch": epoch, "wraps": w}, nil)
	}

	// A member with no published device blocks the first key, and is named.
	err := rotate(ada, "a1", 1, append(ws("ada", "a1"), ws("bob", "b1")...)...)
	if code(err) != "members_without_keys" || !strings.Contains(err.Error(), "cy") {
		t.Fatalf("incomplete rotation: %v", err)
	}
	publish(cy, "c1")
	// With no wraps at all the answer still names who has no key.
	if err := rotate(ada, "a1", 1); code(err) != "members_without_keys" {
		t.Fatalf("a rotation with no wraps: %v", err)
	}
	// Wrapping for a device that is not a member's is refused, and so is a wrong epoch.
	if err := rotate(ada, "a1", 1, append(ws("ada", "a1", "a1x"), ws("bob", "b1")...)...); code(err) != "invalid" {
		t.Fatalf("a wrap for an unpublished device: %v", err)
	}
	all := append(append(ws("ada", "a1"), ws("bob", "b1")...), ws("cy", "c1")...)
	if err := rotate(ada, "a1", 2, all...); code(err) != "stale_epoch" {
		t.Fatalf("skipping an epoch: %v", err)
	}
	if err := rotate(bob, "a1", 1, all...); code(err) != "invalid" {
		t.Fatalf("rotating with someone else's device: %v", err)
	}
	if err := rotate(ada, "a1", 1, all...); err != nil {
		t.Fatal(err)
	}
	bob.next("epoch.new")
	if err := rotate(bob, "b1", 1, all...); code(err) != "stale_epoch" {
		t.Fatalf("two rotations of one epoch: %v", err)
	}

	// Each device gets its own wrap, with the public key to open it by.
	var got struct {
		Epoch int64
		Wraps []struct {
			Epoch    int64
			By       string
			ByDevice string `json:"by_device"`
			ByPub    string `json:"by_pub"`
			ByCert   string `json:"by_cert"`
			W        string
		}
	}
	bob.must("epoch.get", map[string]any{"conv": "c", "device": "b1"}, &got)
	if got.Epoch != 1 || len(got.Wraps) != 1 || got.Wraps[0].W != "wrapped-for-bob-b1" {
		t.Fatalf("bob's wraps: %+v", got)
	}
	if !strings.Contains(string(mustJSON(t, got)), "pub-ada-a1") {
		t.Fatalf("the wrap does not say whose key opens it: %+v", got)
	}
	bob.must("epoch.get", map[string]any{"conv": "c", "device": "a1"}, &got) // not bob's device
	if len(got.Wraps) != 0 {
		t.Fatalf("bob fetched ada's wrap: %+v", got)
	}

	// Messages must name the current epoch.
	send := func(p *peer, id string, epoch int64) error {
		return p.call("msg.send", map[string]any{"conv": "c", "id": id, "body": "x", "epoch": epoch}, nil)
	}
	if err := send(ada, "m0", 0); code(err) != "stale_epoch" {
		t.Fatalf("a message with no epoch: %v", err)
	}
	if err := send(ada, "m1", 1); err != nil {
		t.Fatal(err)
	}

	// cy is removed: their wraps go, and nobody can send until a new epoch exists.
	if _, err := s.acme.RemoveFromConv(bg, "c", "cy"); err != nil {
		t.Fatal(err)
	}
	bob.next("conv.rekey")
	ada.next("conv.rekey")
	if err := send(ada, "m2", 1); code(err) != "rekey_required" {
		t.Fatalf("sent under a key the removed member holds: %v", err)
	}
	if err := cy.call("epoch.get", map[string]any{"conv": "c", "device": "c1"}, nil); code(err) != "forbidden" {
		t.Fatalf("the removed member fetched keys: %v", err)
	}

	// The next epoch excludes them: a wrap for cy's device is refused outright.
	rest := append(ws("ada", "a1"), ws("bob", "b1")...)
	if err := rotate(bob, "b1", 2, append(rest, ws("cy", "c1")...)...); code(err) != "invalid" {
		t.Fatalf("a wrap for the removed member: %v", err)
	}
	if err := rotate(bob, "b1", 2, rest...); err != nil {
		t.Fatal(err)
	}
	ada.next("epoch.new")
	if err := send(ada, "m2", 2); err != nil {
		t.Fatalf("after the rekey: %v", err)
	}
	if err := send(ada, "m3", 1); code(err) != "stale_epoch" {
		t.Fatalf("old epoch after the rekey: %v", err)
	}

	// A member admitted later has no wrap until someone grants one.
	if _, err := s.acme.AdmitToConv(bg, "c", []string{"dee"}, nil); err != nil {
		t.Fatal(err)
	}
	dee := s.dial(s.acme, "dee")
	publish(dee, "d1")
	var miss struct {
		Epoch   int64
		Devices []struct{ User, Device string }
	}
	ada.must("epoch.missing", map[string]any{"conv": "c"}, &miss)
	if miss.Epoch != 2 || len(miss.Devices) != 1 || miss.Devices[0].User != "dee" {
		t.Fatalf("missing: %+v", miss)
	}
	var gr struct{ Added int }
	if err := ada.call("epoch.grant", map[string]any{"conv": "c", "device": "a1", "epoch": 2, "wraps": ws("dee", "d1")}, &gr); err != nil || gr.Added != 1 {
		t.Fatalf("grant: %+v %v", gr, err)
	}
	dee.next("epoch.granted")
	ada.must("epoch.grant", map[string]any{"conv": "c", "device": "a1", "epoch": 2, "wraps": ws("dee", "d1")}, &gr)
	if gr.Added != 0 {
		t.Fatalf("a wrap was replaced: %+v", gr)
	}
	if err := ada.call("epoch.grant", map[string]any{"conv": "c", "device": "a1", "epoch": 3, "wraps": ws("dee", "d1")}, nil); code(err) != "invalid" {
		t.Fatalf("granting an epoch that does not exist: %v", err)
	}
	ada.must("epoch.missing", map[string]any{"conv": "c"}, &miss)
	if len(miss.Devices) != 0 {
		t.Fatalf("still missing: %+v", miss)
	}

	// Revoking a device the conversation relied on forces a new epoch too.
	if err := s.acme.RevokeDevice(bg, "bob", "b1"); err != nil {
		t.Fatal(err)
	}
	ada.next("conv.rekey")
	if err := send(ada, "m4", 2); code(err) != "rekey_required" {
		t.Fatalf("sent after a device was revoked: %v", err)
	}
	if err := rotate(ada, "a1", 3, ws("ada", "a1")...); code(err) != "members_without_keys" {
		t.Fatalf("bob has no device left: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMessagePolicyLifetimeDeleteWindowTypingAndCursors(t *testing.T) {
	s := start(t, nil)
	if _, err := s.acme.OpenConv(bg, client.ConvSpec{ID: "c", Members: []string{"ada", "bob"}}); err != nil {
		t.Fatal(err)
	}
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	var sent struct {
		Seq       int64
		ExpiresAt *time.Time `json:"expires_at"`
	}
	hist := func() []struct {
		Seq     int64
		Expires *time.Time `json:"expires_at"`
	} {
		var h struct {
			Messages []struct {
				Seq     int64
				Expires *time.Time `json:"expires_at"`
			}
		}
		bob.must("msg.history", map[string]any{"conv": "c"}, &h)
		return h.Messages
	}

	// A message can ask to disappear, and says when.
	ada.must("msg.send", map[string]any{"conv": "c", "id": "t", "body": "x", "ttl": 1}, &sent)
	if sent.ExpiresAt == nil || bob.next("msg.new").Data == nil || len(hist()) != 1 || hist()[0].Expires == nil {
		t.Fatalf("a message with a lifetime: %+v", sent)
	}
	if err := ada.call("msg.send", map[string]any{"conv": "c", "id": "n", "body": "x", "ttl": -5}, nil); code(err) != "invalid" {
		t.Fatalf("negative ttl: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if len(hist()) != 0 {
		t.Fatalf("an expired message is still served: %+v", hist())
	}
	if n, err := s.srv.Chat.Prune(bg, 0); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}

	// The conversation's policy: a default lifetime and a delete window.
	if _, err := s.acme.SetConvPolicy(bg, client.ConvSpec{ID: "c", DefaultTTL: ptr(3600), DeleteWindow: ptr(1)}); err != nil {
		t.Fatal(err)
	}
	ada.must("msg.send", map[string]any{"conv": "c", "id": "p", "body": "x"}, &sent)
	if sent.ExpiresAt == nil || time.Until(*sent.ExpiresAt) < 50*time.Minute {
		t.Fatalf("default lifetime not applied: %+v", sent)
	}
	time.Sleep(1200 * time.Millisecond)
	if err := ada.call("msg.delete", map[string]any{"conv": "c", "seq": sent.Seq}, nil); code(err) != "too_late" {
		t.Fatalf("deleted after the window: %v", err)
	}
	ada.must("msg.send", map[string]any{"conv": "c", "id": "q", "body": "x"}, &sent)
	ada.must("msg.delete", map[string]any{"conv": "c", "seq": sent.Seq}, nil)

	// Retention of the conversation alone.
	if _, err := s.acme.SetConvPolicy(bg, client.ConvSpec{ID: "c", Retention: ptr(1), DefaultTTL: ptr(0)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if n, err := s.srv.Chat.Prune(bg, 0); err != nil || n < 2 {
		t.Fatalf("retention prune: %d %v", n, err)
	}
	if _, err := s.acme.OpenConv(bg, client.ConvSpec{ID: "other", Members: []string{"ada"}}); err != nil {
		t.Fatal(err)
	}
	ada.must("msg.send", map[string]any{"conv": "other", "id": "k", "body": "x"}, nil)
	time.Sleep(1100 * time.Millisecond)
	if n, _ := s.srv.Chat.Prune(bg, 0); n != 0 {
		t.Fatalf("another conversation was pruned: %d", n)
	}

	// Typing is relayed to the others, not stored, and not echoed.
	ada.must("msg.typing", map[string]any{"conv": "c"}, nil)
	if ev := bob.next("msg.typing"); field(ev.Data, "user") != "ada" {
		t.Fatalf("typing: %s", ev.Data)
	}
	for deadline := time.After(300 * time.Millisecond); ; {
		select {
		case ev := <-ada.Events():
			if ev.Name == "msg.typing" {
				t.Fatalf("typing was echoed to the typist: %s", ev.Data)
			}
			continue
		case <-deadline:
		}
		break
	}

	// Read positions and the list summary.
	ada.must("msg.send", map[string]any{"conv": "c", "id": "r1", "body": "x"}, &sent)
	ada.must("msg.send", map[string]any{"conv": "c", "id": "r2", "body": "x"}, &sent)
	bob.must("msg.read", map[string]any{"conv": "c", "seq": sent.Seq - 1}, nil)
	var cur struct {
		Cursors []struct {
			User string
			Seq  int64
		}
	}
	ada.must("msg.cursors", map[string]any{"conv": "c"}, &cur)
	if len(cur.Cursors) != 1 || cur.Cursors[0].User != "bob" || cur.Cursors[0].Seq != sent.Seq-1 {
		t.Fatalf("cursors: %+v", cur)
	}
	var sum struct {
		Conversations []struct {
			Conv    string
			LastSeq int64 `json:"last_seq"`
			ReadSeq int64 `json:"read_seq"`
			Unread  int
		}
	}
	bob.must("msg.summary", map[string]any{"convs": []string{"c", "nope"}}, &sum)
	if len(sum.Conversations) != 1 || sum.Conversations[0].LastSeq != sent.Seq || sum.Conversations[0].Unread != 1 {
		t.Fatalf("summary: %+v", sum)
	}
}

func ptr(v int64) *int64 { return &v }

func TestTheWebhookCarriesWhatAPushNeedsAndNoContent(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	var hdr http.Header
	var raw []byte
	hit := make(chan struct{}, 16)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body struct{ Events []map[string]any }
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		got, hdr, raw = append(got, body.Events...), r.Header.Clone(), b
		mu.Unlock()
		hit <- struct{}{}
	}))
	defer hook.Close()
	secret := "webhook-secret-0123456789"
	s := start(t, func(c *server.Config) { c.WebhookURL, c.WebhookSecret = hook.URL, secret })
	if _, err := s.acme.OpenConv(bg, client.ConvSpec{ID: "c", Members: []string{"ada", "bob", "cy"}}); err != nil {
		t.Fatal(err)
	}
	ada, _ := s.dial(s.acme, "ada"), s.dial(s.acme, "bob") // bob is connected, cy is not
	ada.must("msg.send", map[string]any{"conv": "c", "id": "m1", "body": "ciphertext-body", "epoch": 0}, nil)
	select {
	case <-hit:
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook delivery")
	}
	mu.Lock()
	defer mu.Unlock()
	if err := client.VerifyWebhook([]byte(secret), hdr.Get("X-RTC-Timestamp"), hdr.Get("X-RTC-Signature"), raw, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	if client.VerifyWebhook([]byte("another-secret-0123456789"), hdr.Get("X-RTC-Timestamp"), hdr.Get("X-RTC-Signature"), raw, time.Minute, time.Now()) == nil {
		t.Fatal("a signature made with another secret verified")
	}
	if len(got) != 1 {
		t.Fatalf("events: %+v", got)
	}
	e := got[0]
	if e["type"] != "msg.new" || e["conv"] != "c" || e["sender"] != "ada" || e["tenant"] != "acme" || e["seq"].(float64) != 1 {
		t.Fatalf("event: %+v", e)
	}
	if r, _ := e["recipients"].([]any); len(r) != 2 {
		t.Fatalf("recipients: %+v", e)
	}
	if c, _ := e["connected"].([]any); len(c) != 1 || c[0] != "bob" {
		t.Fatalf("connected: %+v", e)
	}
	if strings.Contains(string(raw), "ciphertext-body") {
		t.Fatalf("the webhook carries the message: %s", raw)
	}
}

func TestAWebhookNeedsASecret(t *testing.T) {
	dir := t.TempDir()
	_ = dir
	defer func() { _ = context.Background() }()
	if _, err := server.New(bg, server.Config{DB: testDB(t, t.TempDir(), "w.db", 1), Dialect: dialect(), WebhookURL: "https://example.com/hook",
		Keys: nil}); err == nil {
		t.Fatal("started with a webhook and no keys or secret")
	}
}

func TestLeavingAGroupAUserMadeRekeysItToo(t *testing.T) {
	s := start(t, nil)
	ada, bob, cy := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "cy")
	g := group(t, ada, "bob", "cy")
	publish(ada, "a1")
	publish(bob, "b1")
	publish(cy, "c1")
	all := append(append(ws("ada", "a1"), ws("bob", "b1")...), ws("cy", "c1")...)
	ada.must("epoch.rotate", map[string]any{"conv": g, "device": "a1", "epoch": 1, "wraps": all}, nil)
	ada.must("msg.send", map[string]any{"conv": g, "id": "m", "body": "x", "epoch": 1}, nil)

	cy.must("group.remove", map[string]any{"group": g, "users": []string{"cy"}}, nil) // leaving
	bob.next("conv.rekey")
	if err := ada.call("msg.send", map[string]any{"conv": g, "id": "n", "body": "x", "epoch": 1}, nil); code(err) != "rekey_required" {
		t.Fatalf("sent after someone left: %v", err)
	}
	ada.must("epoch.rotate", map[string]any{"conv": g, "device": "a1", "epoch": 2, "wraps": append(ws("ada", "a1"), ws("bob", "b1")...)}, nil)
	ada.must("msg.send", map[string]any{"conv": g, "id": "n", "body": "x", "epoch": 2}, nil)

	// Deleting the group deletes what was kept for it.
	ada.must("group.delete", map[string]any{"group": g}, nil)
	var n int
	_ = s.adb // the audit database is separate; the chat tables share the main one
	row := s.srv.Chat
	if h, err := row.History(bg, "acme", g, 0, 0, 10); err != nil || len(h) != 0 {
		t.Fatalf("messages of a deleted group: %+v %v", h, err)
	}
	if st, _ := row.Fresh(bg, "acme", g); st.Epoch != 0 {
		t.Fatalf("epoch of a deleted group: %+v", st)
	}
	_ = n
}

func TestWithAnEdgeSecretTheServiceAnswersOnlyThoseWhoHoldIt(t *testing.T) {
	const edge = "edge-secret-0123456789-abcdefghij"
	s := start(t, func(c *server.Config) { c.EdgeSecret = edge })
	s.acme.EdgeSecret = edge // the backend's own client carries it
	do := func(method, path, auth, edgeHdr string) int {
		req, _ := http.NewRequest(method, s.base+path, strings.NewReader(`{"user":"ada"}`))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if edgeHdr != "" {
			req.Header.Set("X-RTC-Edge", edgeHdr)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}

	// Health checks are open: they say nothing and orchestrators need them.
	if c := do("GET", "/healthz", "", ""); c != 200 {
		t.Fatalf("healthz: %d", c)
	}
	// Everything else needs the secret, whatever credential comes with it: a service key, a user token, none.
	user := s.token("ada")
	for name, auth := range map[string]string{"no credential": "", "service key": acmeKey, "user token": user} {
		for _, p := range []string{"/v1/tokens", "/v1/stats", "/v1/conversations/open", "/v1/ws", "/v1/ws/ticket", "/v1/files", "/v1/messages", "/v1/calls"} {
			if c := do("POST", p, auth, ""); c != 403 {
				t.Fatalf("%s to %s without the secret: %d", name, p, c)
			}
			if c := do("POST", p, auth, "wrong-secret-0123456789-abcdefghij"); c != 403 {
				t.Fatalf("%s to %s with the wrong secret: %d", name, p, c)
			}
		}
	}
	if c := do("GET", "/v1/ws?token="+user, "", ""); c != 403 {
		t.Fatalf("a websocket without the secret: %d", c)
	}
	// With it, the service works as before.
	if c := do("POST", "/v1/tokens", acmeKey, edge); c != 200 {
		t.Fatalf("token with the secret: %d", c)
	}
	if c := do("POST", "/v1/ws/ticket", user, edge); c != 200 {
		t.Fatalf("ticket with the secret: %d", c)
	}
	// and a secret that is too short is refused at startup
	if _, err := server.New(bg, server.Config{DB: testDB(t, t.TempDir(), "e.db", 1), Dialect: dialect(), EdgeSecret: "short",
		Keys: []auth.ServiceKey{{Name: "chat", Key: acmeKey, Tenant: "acme"}}, TokenSecret: "token-secret-token-secret-0123456"}); err == nil {
		t.Fatal("started with a short edge secret")
	}
}

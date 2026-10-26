package server_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/rtcd/client"
	"github.com/oarkflow/rtcd/server"
	"golang.org/x/net/websocket"
)

func wsDial(u string) (*websocket.Conn, error) {
	cfg, err := websocket.NewConfig(u, origin)
	if err != nil {
		return nil, err
	}
	return websocket.DialConfig(cfg)
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// api calls an HTTP route as a user with a token.
func (s *svc) api(token, method, path string, body []byte, hdr map[string]string) (int, []byte) {
	s.t.Helper()
	req, _ := http.NewRequest(method, s.base+path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil && method != "PUT" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func (s *svc) token(user string) string {
	tok, err := s.acme.Token(bg, user, time.Minute)
	if err != nil {
		s.t.Fatal(err)
	}
	return tok.Token
}

func group(t *testing.T, p *peer, members ...string) string {
	var g struct{ ID string }
	p.must("group.create", map[string]any{"name": "g", "members": members}, &g)
	return g.ID
}

func TestMessagesGoToMembersOnlyAndAreStoredOpaquely(t *testing.T) {
	s := start(t, nil)
	ada, bob, eve := s.dial(s.acme, "ada"), s.dial(s.acme, "bob"), s.dial(s.acme, "eve")
	g := group(t, ada, "bob")

	var sent struct {
		Seq       int64
		Duplicate bool
	}
	ada.must("msg.send", map[string]any{"conv": g, "id": "m1", "body": "v1.ciphertext=="}, &sent)
	if sent.Seq != 1 {
		t.Fatalf("first message: %+v", sent)
	}
	ev := bob.next("msg.new")
	if field(ev.Data, "body") != "v1.ciphertext==" || field(ev.Data, "sender") != "ada" || ev.From != "ada" {
		t.Fatalf("event: %s", ev.Data)
	}
	// A retry (the answer was lost) neither duplicates nor renumbers.
	ada.must("msg.send", map[string]any{"conv": g, "id": "m1", "body": "v1.ciphertext=="}, &sent)
	if !sent.Duplicate || sent.Seq != 1 {
		t.Fatalf("retry: %+v", sent)
	}
	bob.must("msg.send", map[string]any{"conv": g, "id": "m1", "body": "x"}, &sent) // another sender's same id
	if sent.Seq != 2 {
		t.Fatalf("second sender: %+v", sent)
	}

	// A stranger can neither send, read, nor tell the group exists.
	if err := eve.call("msg.send", map[string]any{"conv": g, "id": "e", "body": "x"}, nil); code(err) != "forbidden" {
		t.Fatalf("eve sent: %v", err)
	}
	if err := eve.call("msg.history", map[string]any{"conv": g}, nil); code(err) != "forbidden" {
		t.Fatalf("eve read: %v", err)
	}
	// Bad input.
	if err := ada.call("msg.send", map[string]any{"conv": g, "id": "big", "body": strings.Repeat("a", 33<<10)}, nil); code(err) != "invalid" {
		t.Fatalf("oversize body: %v", err)
	}
	if err := ada.call("msg.send", map[string]any{"conv": g, "body": "x"}, nil); code(err) != "invalid" {
		t.Fatalf("no id: %v", err)
	}

	var h struct {
		Messages []struct {
			Seq  int64
			Body string
		}
	}
	bob.must("msg.history", map[string]any{"conv": g, "after": 0}, &h)
	if len(h.Messages) != 2 || h.Messages[0].Seq != 1 {
		t.Fatalf("history: %+v", h)
	}
	bob.must("msg.history", map[string]any{"conv": g, "before": 2, "limit": 10}, &h)
	if len(h.Messages) != 1 || h.Messages[0].Seq != 1 {
		t.Fatalf("history before: %+v", h)
	}

	// Only the sender (or an admin) deletes.
	if err := bob.call("msg.delete", map[string]any{"conv": g, "seq": 1}, nil); code(err) != "forbidden" {
		t.Fatalf("bob deleted ada's message: %v", err)
	}
	ada.must("msg.delete", map[string]any{"conv": g, "seq": 2}, nil) // the owner may remove anyone's
	bob.next("msg.deleted")
	bob.must("msg.read", map[string]any{"conv": g, "seq": 1}, nil)

	// Removal takes effect on the next message, not in a few seconds.
	ada.must("group.remove", map[string]any{"group": g, "users": []string{"bob"}}, nil)
	if err := bob.call("msg.send", map[string]any{"conv": g, "id": "late", "body": "x"}, nil); code(err) != "forbidden" {
		t.Fatalf("a removed member sent: %v", err)
	}
	// The log never holds a body.
	evs, _ := s.acme.Audit(bg, client.AuditFilter{Action: "msg."})
	for _, e := range evs {
		if b, _ := json.Marshal(e); strings.Contains(string(b), "ciphertext") {
			t.Fatalf("audit holds content: %s", b)
		}
	}
}

func TestAnAttachmentUploadsResumesVerifiesAndDownloadsOnlyForMembers(t *testing.T) {
	s := start(t, func(c *server.Config) { c.AttachDir = t.TempDir() })
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	g := group(t, ada, "bob")
	at, bt, et := s.token("ada"), s.token("bob"), s.token("eve")

	data := make([]byte, 2500)
	for i := range data {
		data[i] = byte(i * 7)
	}
	var init struct {
		File   struct{ ID string }
		Chunks int
	}
	ada.must("file.init", map[string]any{"conv": g, "size": len(data), "sha256": sum(data), "chunk": 1000}, &init)
	if init.Chunks != 3 {
		t.Fatalf("init: %+v", init)
	}
	part := func(tok string, n int) int {
		lo, hi := n*1000, (n+1)*1000
		if hi > len(data) {
			hi = len(data)
		}
		c, _ := s.api(tok, "PUT", fmt.Sprintf("/v1/files/%s/parts/%d", init.File.ID, n), data[lo:hi], nil)
		return c
	}
	if c := part(at, 0); c != 200 {
		t.Fatalf("part 0: %d", c)
	}
	if c := part(bt, 1); c != 404 {
		t.Fatalf("someone else's upload: %d", c)
	}
	if c, _ := s.api(at, "PUT", fmt.Sprintf("/v1/files/%s/parts/1", init.File.ID), []byte("short"), nil); c != 400 {
		t.Fatalf("a wrong-sized part: %d", c)
	}
	// Complete too early; then resume from what the server has.
	if err := ada.call("file.complete", map[string]any{"file": init.File.ID}, nil); code(err) != "parts_missing" {
		t.Fatalf("early complete: %v", err)
	}
	var st struct{ Have []int }
	ada.must("file.status", map[string]any{"file": init.File.ID}, &st)
	if len(st.Have) != 1 || st.Have[0] != 0 {
		t.Fatalf("status: %+v", st)
	}
	part(at, 2)
	part(at, 1)
	// It is not downloadable until verified.
	if c, _ := s.api(bt, "GET", "/v1/files/"+init.File.ID+"/blob", nil, nil); c != 409 {
		t.Fatalf("download before complete: %d", c)
	}
	ada.must("file.complete", map[string]any{"file": init.File.ID}, nil)

	c, got := s.api(bt, "GET", "/v1/files/"+init.File.ID+"/blob", nil, nil)
	if c != 200 || !bytes.Equal(got, data) {
		t.Fatalf("member download: %d, %d bytes", c, len(got))
	}
	if c, got := s.api(bt, "GET", "/v1/files/"+init.File.ID+"/blob", nil, map[string]string{"Range": "bytes=100-199"}); c != 206 || !bytes.Equal(got, data[100:200]) {
		t.Fatalf("range: %d", c)
	}
	if c, _ := s.api(et, "GET", "/v1/files/"+init.File.ID+"/blob", nil, nil); c != 404 {
		t.Fatalf("a stranger downloaded: %d", c)
	}
	if c, _ := s.api("", "GET", "/v1/files/"+init.File.ID+"/blob", nil, nil); c != 401 {
		t.Fatalf("anonymous download: %d", c)
	}

	// A link works without a header, for that user, and only untampered.
	var link struct{ URL string }
	bob.must("file.link", map[string]any{"file": init.File.ID}, &link)
	if c, got := s.api("", "GET", link.URL, nil, nil); c != 200 || !bytes.Equal(got, data) {
		t.Fatalf("link: %d", c)
	}
	if c, _ := s.api("", "GET", strings.Replace(link.URL, "u=bob", "u=eve", 1), nil, nil); c != 401 {
		t.Fatalf("a link for another user: %d", c)
	}
	// Removed from the group, the link stops working too.
	ada.must("group.remove", map[string]any{"group": g, "users": []string{"bob"}}, nil)
	if c, _ := s.api("", "GET", link.URL, nil, nil); c != 404 {
		t.Fatalf("a removed member's link: %d", c)
	}
}

func TestAnUploadThatIsNotWhatWasAnnouncedIsDiscarded(t *testing.T) {
	s := start(t, func(c *server.Config) { c.AttachDir = t.TempDir(); c.MaxFileBytes = 5000 })
	ada := s.dial(s.acme, "ada")
	g := group(t, ada, "bob")
	at := s.token("ada")
	data := bytes.Repeat([]byte("a"), 100)
	var init struct{ File struct{ ID string } }
	ada.must("file.init", map[string]any{"conv": g, "size": 100, "sha256": sum([]byte("something else"))}, &init)
	if c, _ := s.api(at, "PUT", "/v1/files/"+init.File.ID+"/parts/0", data, nil); c != 200 {
		t.Fatalf("part: %d", c)
	}
	if err := ada.call("file.complete", map[string]any{"file": init.File.ID}, nil); code(err) != "checksum_mismatch" {
		t.Fatalf("complete: %v", err)
	}
	if err := ada.call("file.status", map[string]any{"file": init.File.ID}, nil); code(err) != "not_found" {
		t.Fatalf("the bad file survived: %v", err)
	}
	if err := ada.call("file.init", map[string]any{"conv": g, "size": 6000, "sha256": sum(data)}, nil); code(err) != "invalid" {
		t.Fatalf("over the size cap: %v", err)
	}
	for i := 0; i < 10; i++ {
		ada.must("file.init", map[string]any{"conv": g, "size": 10, "sha256": sum(data)}, nil)
	}
	if err := ada.call("file.init", map[string]any{"conv": g, "size": 10, "sha256": sum(data)}, nil); code(err) != "limit_reached" {
		t.Fatalf("too many open uploads: %v", err)
	}
}

func TestATicketOpensOneConnectionOnceAndARevokedUserIsCutOff(t *testing.T) {
	s := start(t, nil)
	tok := s.token("ada")
	code1, body := s.api(tok, "POST", "/v1/ws/ticket", []byte("{}"), nil)
	if code1 != 200 {
		t.Fatalf("ticket: %d %s", code1, body)
	}
	var tk struct{ Ticket string }
	_ = json.Unmarshal(body, &tk)
	url := strings.Replace(s.base, "http", "ws", 1) + "/v1/ws?ticket=" + tk.Ticket
	dialWS := func(u string) error {
		conn, err := wsDial(u)
		if err == nil {
			conn.Close()
		}
		return err
	}
	if err := dialWS(url); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := dialWS(url); err == nil {
		t.Fatal("a ticket was used twice")
	}

	// Revocation: the live connection closes and the old token is refused.
	ada := s.dial(s.acme, "ada")
	if c, b := s.api(acmeKey, "POST", "/v1/tokens/revoke", []byte(`{"user":"ada"}`), nil); c != 200 {
		t.Fatalf("revoke: %d %s", c, b)
	}
	select {
	case <-ada.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a revoked user stayed connected")
	}
	if c, _ := s.api(tok, "POST", "/v1/ice", []byte("{}"), nil); c != 401 {
		t.Fatalf("a revoked token: %d", c)
	}
	if c, _ := s.api(s.token("ada"), "POST", "/v1/ice", []byte("{}"), nil); c != 200 {
		t.Fatalf("a new token after revocation: %d", c)
	}
}

func TestAddressThatKeepsFailingToSignInIsThrottled(t *testing.T) {
	s := start(t, nil)
	var last int
	for i := 0; i < 40; i++ {
		last, _ = s.api("not-a-real-token-0123456789abcdef", "POST", "/v1/ice", []byte("{}"), nil)
	}
	if last != 429 {
		t.Fatalf("after 40 failures: %d", last)
	}
}

func TestBigRoomsGetPeerChangesInBatches(t *testing.T) {
	s := start(t, nil)
	const n = 30
	users := manyUsers(n)
	peers := make([]*peer, n)
	for i, u := range users {
		peers[i] = s.dial(s.acme, u)
	}
	s.srv.RoomForTest("big", "acme")
	for i, u := range users {
		_ = s.srv.Peer("big", u, true, users[:i+1])
	}
	// Everyone hears of the 14 arrivals after the 16th at once, not 14 events.
	time.Sleep(600 * time.Millisecond)
	singles, batches := 0, 0
	for {
		select {
		case ev := <-peers[0].Events():
			switch ev.Name {
			case "sfu.peer":
				singles++
			case "sfu.peers":
				batches++
			}
			continue
		default:
		}
		break
	}
	if singles > 16 || batches == 0 || batches > 2 {
		t.Fatalf("u000 saw %d single events and %d batches", singles, batches)
	}
}

func TestOneTenantCannotFillTheNode(t *testing.T) {
	s := start(t, func(c *server.Config) { c.MaxConnsPerTenant = 2 })
	s.dial(s.acme, "a")
	s.dial(s.acme, "b")
	tok, _ := s.acme.Token(bg, "c", time.Minute)
	if _, err := client.NewUser(s.base, tok.Token).Dial(bg, client.DialOptions{Origin: origin}); err == nil {
		t.Fatal("a third connection for a tenant capped at two")
	}
	s.dial(s.zeta, "a") // another tenant is unaffected
}

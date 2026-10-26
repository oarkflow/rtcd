package server_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/client"
	"github.com/oarkflow/rtcd/server"
	"github.com/pion/webrtc/v4"
	_ "modernc.org/sqlite"
)

const (
	acmeKey = "acme-service-key-0123456789ab"
	zetaKey = "zeta-service-key-0123456789ab"
	origin  = "https://app.example.com"
)

type svc struct {
	t    testing.TB
	base string
	acme *client.Client
	zeta *client.Client
	srv  *server.Server
	adb  *sql.DB
}

func start(t *testing.T, tweak func(*server.Config)) *svc { return startTB(t, tweak) }

func startTB(t testing.TB, tweak func(*server.Config)) *svc {
	t.Helper()
	dir := t.TempDir()
	open := func(name string, conns int) *sql.DB { return testDB(t, dir, name, conns) }
	adb := open("a.db", 1)
	cfg := server.Config{
		DB: open("r.db", 1), AuditDB: adb, Dialect: dialect(), TokenSecret: "token-secret-token-secret-0123456",
		Keys:           []auth.ServiceKey{{Name: "chat", Key: acmeKey, Tenant: "acme"}, {Name: "shop", Key: zetaKey, Tenant: "zeta"}},
		AllowedOrigins: []string{origin},
		RecordDir:      t.TempDir(),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	s, err := server.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	app := fh.NewFast()
	s.Mount(app)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ln) }()
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(time.Second); _ = ln.Close() })
	base := "http://" + ln.Addr().String()
	return &svc{t: t, base: base, acme: client.New(base, acmeKey), zeta: client.New(base, zetaKey), srv: s, adb: adb}
}

var bg = context.Background()

// peer is a user connected over a WebSocket.
type peer struct {
	t    testing.TB
	user string
	*client.Conn
}

// dial connects a user the way a browser does: with a token the backend minted.
func (s *svc) dial(c *client.Client, user string) *peer {
	s.t.Helper()
	tok, err := c.Token(bg, user, time.Minute)
	if err != nil {
		s.t.Fatal(err)
	}
	conn, err := client.NewUser(s.base, tok.Token).Dial(bg, client.DialOptions{Origin: origin})
	if err != nil {
		s.t.Fatalf("dial %s: %v", user, err)
	}
	s.t.Cleanup(conn.Close)
	return &peer{t: s.t, user: user, Conn: conn}
}

func (p *peer) call(op string, in any, out any) error { return p.Call(bg, op, in, out) }

func (p *peer) must(op string, in any, out any) {
	p.t.Helper()
	if err := p.call(op, in, out); err != nil {
		p.t.Fatalf("%s %s: %v", p.user, op, err)
	}
}

func (p *peer) next(name string) client.Event {
	p.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-p.Events():
			if !ok {
				p.t.Fatalf("%s: the connection closed waiting for %q: %v", p.user, name, p.Err())
			}
			if ev.Name == name {
				return ev
			}
		case <-deadline:
			p.t.Fatalf("%s: no %q event arrived", p.user, name)
		}
	}
}

func (p *peer) none(d time.Duration) {
	p.t.Helper()
	select {
	case ev := <-p.Events():
		p.t.Fatalf("%s: an unexpected event arrived: %s %s", p.user, ev.Name, ev.Data)
	case <-time.After(d):
	}
}

func field(raw json.RawMessage, path ...string) any {
	var v any
	_ = json.Unmarshal(raw, &v)
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

type startReply struct {
	Call client.Call        `json:"call"`
	ICE  []client.ICEServer `json:"ice"`
}

func code(err error) string {
	var ce *client.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

func TestAWholeP2PCallRunsOverWebSockets(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")

	var started startReply
	ada.must("call.start", map[string]any{"to": []string{"bob"}, "kind": "video", "mode": "p2p"}, &started)
	if !started.Call.E2EE || started.Call.Status != "ringing" || started.Call.Initiator != "ada" {
		t.Fatalf("%+v", started.Call)
	}
	id := started.Call.ID
	in := bob.next("call.incoming")
	if in.From != "ada" || field(in.Data, "call", "id") != id {
		t.Fatalf("%s", in.Data)
	}
	bob.must("call.answer", map[string]any{"call": id}, nil)
	ada.next("call.answered")
	// Everything a call needs goes over the same socket.
	ada.must("call.signal", map[string]any{"call": id, "to": "bob", "type": "offer", "data": map[string]any{"sdp": "v=0"}}, nil)
	sig := bob.next("call.signal")
	if field(sig.Data, "from") != "ada" || field(sig.Data, "type") != "offer" {
		t.Fatalf("%s", sig.Data)
	}
	blob := `{"v":1,"t":"hello","ct":"opaque"}`
	bob.must("call.e2ee", map[string]any{"call": id, "to": "ada", "data": blob}, nil)
	if got := field(ada.next("call.e2ee").Data, "data"); got != blob {
		t.Fatalf("key message changed in transit: %v", got)
	}
	var got client.Call
	ada.must("call.get", map[string]any{"call": id}, &got)
	if got.Status != "active" {
		t.Fatalf("%+v", got)
	}
	bob.must("call.end", map[string]any{"call": id}, nil)
	ada.next("call.ended")
	// Ending twice is harmless; a stranger learns nothing.
	bob.must("call.end", map[string]any{"call": id}, nil)
	eve := s.dial(s.acme, "eve")
	if err := eve.call("call.get", map[string]any{"call": id}, nil); code(err) != "forbidden" {
		t.Fatalf("a stranger: %v", err)
	}
	if err := eve.call("call.get", map[string]any{"call": "call_nope"}, nil); code(err) != "forbidden" {
		t.Fatalf("an unknown call must look the same: %v", err)
	}
}

func TestTheBackendCanDriveTheSameOperationsOverHTTP(t *testing.T) {
	s := start(t, nil)
	bob := s.dial(s.acme, "bob")
	started, err := s.acme.As("ada").Start(bg, client.StartRequest{To: []string{"bob"}, Mode: "p2p"})
	if err != nil {
		t.Fatal(err)
	}
	bob.next("call.incoming")
	if _, err := s.acme.As("bob").Answer(bg, started.Call.ID); err != nil {
		t.Fatal(err)
	}
	var c client.Call
	bob.must("call.get", map[string]any{"call": started.Call.ID}, &c)
	if c.Status != "active" {
		t.Fatalf("the two interfaces disagree: %+v", c)
	}
	// A service can also hold a socket as one of its users.
	conn, err := s.acme.As("ada").Dial(bg, client.DialOptions{Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if field(conn.Ready().Data, "user") != "ada" || field(conn.Ready().Data, "tenant") != "acme" {
		t.Fatalf("%s", conn.Ready().Data)
	}
}

func TestOnlyAServiceKeyMintsTokensAndATokenIsOneUser(t *testing.T) {
	s := start(t, nil)
	tok, err := s.acme.Token(bg, "ada", time.Minute)
	if err != nil || tok.User != "ada" || tok.Tenant != "acme" || !tok.ExpiresAt.After(time.Now()) {
		t.Fatalf("%+v %v", tok, err)
	}
	if _, err := client.New(s.base, tok.Token).Token(bg, "bob", time.Minute); !errors.Is(err, client.ErrForbidden) {
		t.Fatalf("a user minted a token: %v", err)
	}
	if _, err := client.New(s.base, "not-a-real-key-not-a-real-key").Token(bg, "bob", time.Minute); !errors.Is(err, client.ErrUnauthenticated) {
		t.Fatalf("a bad key: %v", err)
	}
	long, _ := s.acme.Token(bg, "ada", 1000*time.Hour)
	if time.Until(long.ExpiresAt) > 61*time.Minute {
		t.Fatalf("a token lives %v", time.Until(long.ExpiresAt))
	}
	for _, user := range []string{"", "a\x1fb"} {
		if _, err := s.acme.Token(bg, user, time.Minute); !errors.Is(err, client.ErrInvalid) {
			t.Errorf("token for %q: %v", user, err)
		}
	}
	// Over a socket the same: a token cannot mint, and it acts as its own user only.
	conn := s.dial(s.acme, "ada")
	if err := conn.call("token.mint", map[string]any{"user": "bob"}, nil); code(err) != "service_key_required" {
		t.Fatalf("%v", err)
	}
	if err := conn.call("audit.query", map[string]any{}, nil); code(err) != "service_key_required" {
		t.Fatalf("a user read the audit log: %v", err)
	}
	if err := conn.call("stats", map[string]any{}, nil); code(err) != "service_key_required" {
		t.Fatalf("%v", err)
	}
	// A service key must say who it acts for.
	req, _ := http.NewRequest("POST", s.base+"/v1/calls", strings.NewReader(`{"to":["bob"]}`))
	req.Header.Set("Authorization", "Bearer "+acmeKey)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Fatalf("a service without X-RTC-User: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestTenantsAreFullyIsolated(t *testing.T) {
	s := start(t, nil)
	// acme and zeta both have users named ada and bob.
	zetaBob, acmeBob, acmeAda := s.dial(s.zeta, "bob"), s.dial(s.acme, "bob"), s.dial(s.acme, "ada")
	var started startReply
	acmeAda.must("call.start", map[string]any{"to": []string{"bob"}}, &started)
	acmeBob.next("call.incoming")
	zetaBob.none(400 * time.Millisecond) // zeta's bob is a different person
	id := started.Call.ID
	for _, u := range []string{"ada", "bob"} {
		z := s.dial(s.zeta, u)
		for op, in := range map[string]any{
			"call.get": map[string]any{"call": id}, "call.answer": map[string]any{"call": id}, "call.end": map[string]any{"call": id},
			"call.e2ee": map[string]any{"call": id, "to": "ada", "data": "x"}, "sfu.stats": map[string]any{"call": id},
			"call.signal": map[string]any{"call": id, "to": "bob", "type": "offer", "data": map[string]any{}},
		} {
			if err := z.call(op, in, nil); code(err) != "forbidden" {
				t.Errorf("zeta %s %s: %v", u, op, err)
			}
		}
	}
	var c client.Call
	acmeAda.must("call.get", map[string]any{"call": id}, &c)
	if c.Status == "ended" {
		t.Fatal("the call was ended by another tenant")
	}
}

func TestEncryptionIsRequiredUnlessThePlatformAllowsPlaintext(t *testing.T) {
	s := start(t, nil)
	off := false
	if _, err := s.acme.As("ada").Start(bg, client.StartRequest{To: []string{"bob"}, E2EE: &off}); !errors.Is(err, client.ErrInvalid) {
		t.Fatalf("a plaintext call on a default service: %v", err)
	}
	p := start(t, func(c *server.Config) { c.AllowPlaintext = true })
	c, err := p.acme.As("ada").Start(bg, client.StartRequest{To: []string{"bob"}, E2EE: &off})
	if err != nil || c.Call.E2EE {
		t.Fatalf("%+v %v", c, err)
	}
	if c2, _ := p.acme.As("ada").Start(bg, client.StartRequest{To: []string{"cy"}}); c2.Call.E2EE {
		t.Fatal("a service that allows plaintext should not turn it on by itself")
	}
}

func TestBadInputIsRefusedNotCrashed(t *testing.T) {
	s := start(t, nil)
	ada := s.dial(s.acme, "ada")
	for name, in := range map[string]map[string]any{
		"nobody":          {"to": []string{}},
		"yourself":        {"to": []string{"ada"}},
		"p2p with three":  {"to": []string{"bob", "cy"}, "mode": "p2p"},
		"a bad user name": {"to": []string{"b\x1fb"}},
		"bad kind":        {"to": []string{"bob"}, "kind": "hologram"},
		"bad mode":        {"to": []string{"bob"}, "mode": "mesh"},
	} {
		if err := ada.call("call.start", in, nil); code(err) != "invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ada.call("no.such.thing", map[string]any{}, nil); err == nil {
		t.Error("an unknown operation was accepted")
	}
	// Over HTTP: malformed and oversized bodies, a wrong content type.
	for _, body := range []string{"{", "[]", `{"to":"bob"}`, strings.Repeat("x", 70<<10)} {
		req, _ := http.NewRequest("POST", s.base+"/v1/calls", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+acmeKey)
		req.Header.Set("X-RTC-User", "ada")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Errorf("body %.20q: %d", body, resp.StatusCode)
		}
		resp.Body.Close()
	}
	req, _ := http.NewRequest("POST", s.base+"/v1/calls", strings.NewReader(`{"to":["bob"]}`))
	req.Header.Set("Authorization", "Bearer "+acmeKey)
	req.Header.Set("X-RTC-User", "ada")
	req.Header.Set("Content-Type", "text/plain")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 415 {
		t.Errorf("text/plain: %d", resp.StatusCode)
	}
	resp.Body.Close()
	// The socket survives all of it.
	var c client.Call
	if err := ada.call("ice", nil, nil); err != nil {
		t.Fatalf("the connection did not survive bad input: %v", err)
	}
	_ = c
}

func TestBrowsersMayConnectFromAllowedOriginsOnly(t *testing.T) {
	s := start(t, nil)
	do := func(method, o string) *http.Response {
		req, _ := http.NewRequest(method, s.base+"/v1/ice", nil)
		if o != "" {
			req.Header.Set("Origin", o)
		}
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := do("OPTIONS", origin); r.StatusCode != 204 || r.Header.Get("Access-Control-Allow-Origin") != origin ||
		!strings.Contains(r.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("allowed preflight: %d %v", r.StatusCode, r.Header)
	}
	if r := do("OPTIONS", "https://evil.example.com"); r.StatusCode != 403 || r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("refused preflight: %d %v", r.StatusCode, r.Header)
	}
	tok, _ := s.acme.Token(bg, "bob", time.Minute)
	for _, o := range []string{"https://evil.example.com", "http://localhost"} {
		if c, err := client.NewUser(s.base, tok.Token).Dial(bg, client.DialOptions{Origin: o}); err == nil {
			c.Close()
			t.Errorf("a socket from %s was accepted", o)
		}
	}
}

func TestSocketsNeedValidCredentialsAndAreLimited(t *testing.T) {
	s := start(t, func(c *server.Config) { c.MaxConnsPerUser = 3 })
	for name, u := range map[string]*client.User{
		"garbage":                      client.NewUser(s.base, "garbage-garbage-garbage-garbage"),
		"empty":                        client.NewUser(s.base, ""),
		"a service key without a user": client.NewUser(s.base, acmeKey),
	} {
		if c, err := u.Dial(bg, client.DialOptions{Origin: origin}); err == nil {
			c.Close()
			t.Errorf("%s: connected", name)
		}
	}
	tok, _ := s.acme.Token(bg, "bob", time.Minute)
	var keep []*client.Conn
	for i := 0; i < 3; i++ {
		c, err := client.NewUser(s.base, tok.Token).Dial(bg, client.DialOptions{Origin: origin})
		if err != nil {
			t.Fatal(err)
		}
		keep = append(keep, c)
		defer c.Close()
	}
	if c, err := client.NewUser(s.base, tok.Token).Dial(bg, client.DialOptions{Origin: origin}); err == nil {
		c.Close()
		t.Fatal("a fourth connection was accepted")
	}
	// Another user is unaffected, and so is the same name in another tenant.
	s.dial(s.acme, "cy")
	s.dial(s.zeta, "bob")
	// Each connection of one user hears the same events.
	ada := s.dial(s.acme, "ada")
	var st startReply
	ada.must("call.start", map[string]any{"to": []string{"bob"}}, &st)
	for i, c := range keep {
		select {
		case ev := <-c.Events():
			if ev.Name != "call.incoming" {
				t.Fatalf("connection %d: %s", i, ev.Name)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("connection %d heard nothing", i)
		}
	}
}

func TestATokenThatRunsOutClosesTheSocketUnlessRefreshed(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := start(t, func(c *server.Config) { c.Now = clock })
	tok, _ := s.acme.Token(bg, "ada", time.Minute)
	conn, err := client.NewUser(s.base, tok.Token).Dial(bg, client.DialOptions{Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Call(bg, "ice", nil, nil); err != nil {
		t.Fatal(err)
	}
	// A refresh with another user's token, or a bad one, changes nothing.
	other, _ := s.acme.Token(bg, "bob", time.Hour)
	if err := conn.Call(bg, "auth.refresh", map[string]any{"token": other.Token}, nil); code(err) != "unauthenticated" {
		t.Fatalf("refreshed with somebody else's token: %v", err)
	}
	if err := conn.Call(bg, "auth.refresh", map[string]any{"token": "nope"}, nil); code(err) != "unauthenticated" {
		t.Fatalf("%v", err)
	}
	fresh, _ := s.acme.Token(bg, "ada", time.Hour)
	if err := conn.Call(bg, "auth.refresh", map[string]any{"token": fresh.Token}, nil); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // the first token is long over; the refreshed one is not
	if err := conn.Call(bg, "ice", nil, nil); err != nil {
		t.Fatalf("a refreshed connection stopped working: %v", err)
	}
	// Without a refresh the operations stop at once and the socket is closed soon after.
	short, _ := s.acme.Token(bg, "cy", time.Minute)
	c2, _ := client.NewUser(s.base, short.Token).Dial(bg, client.DialOptions{Origin: origin})
	defer c2.Close()
	now = now.Add(2 * time.Minute)
	if err := c2.Call(bg, "ice", nil, nil); code(err) != "token_expired" {
		t.Fatalf("an expired token still works: %v", err)
	}
	select {
	case <-c2.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("the connection outlived its token")
	}
}

func TestScopesLimitWhatATokenMayDo(t *testing.T) {
	s := start(t, nil)
	callsOnly, _ := s.acme.Token(bg, "ada", time.Minute, "calls")
	groupsOnly, _ := s.acme.Token(bg, "bob", time.Minute, "groups")
	a, _ := client.NewUser(s.base, callsOnly.Token).Dial(bg, client.DialOptions{Origin: origin})
	b, _ := client.NewUser(s.base, groupsOnly.Token).Dial(bg, client.DialOptions{Origin: origin})
	defer a.Close()
	defer b.Close()
	if err := a.Call(bg, "group.create", map[string]any{"name": "x"}, nil); code(err) != "scope_missing" {
		t.Fatalf("%v", err)
	}
	if err := b.Call(bg, "call.start", map[string]any{"to": []string{"cy"}}, nil); code(err) != "scope_missing" {
		t.Fatalf("%v", err)
	}
	if err := a.Call(bg, "call.start", map[string]any{"to": []string{"cy"}}, nil); err != nil {
		t.Fatalf("%v", err)
	}
	var g struct{ ID string }
	if err := b.Call(bg, "group.create", map[string]any{"name": "x"}, &g); err != nil || g.ID == "" {
		t.Fatalf("%v", err)
	}
	// group.call needs both.
	if err := b.Call(bg, "group.call", map[string]any{"group": g.ID}, nil); code(err) != "scope_missing" {
		t.Fatalf("group.call with only the groups scope: %v", err)
	}
	if _, err := s.acme.Token(bg, "x", time.Minute, "admin"); !errors.Is(err, client.ErrInvalid) {
		t.Fatalf("an unknown scope: %v", err)
	}
}

func TestLargeMessagesGoThroughTheSocket(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	var st startReply
	ada.must("call.start", map[string]any{"to": []string{"bob"}}, &st)
	bob.next("call.incoming")
	bob.must("call.answer", map[string]any{"call": st.Call.ID}, nil)
	big := strings.Repeat("a", 15<<10)
	ada.must("call.e2ee", map[string]any{"call": st.Call.ID, "to": "bob", "data": big}, nil)
	if got := field(bob.next("call.e2ee").Data, "data"); got != big {
		t.Fatalf("a %d byte message arrived as %d bytes", len(big), len(got.(string)))
	}
	sdp := map[string]any{"sdp": strings.Repeat("a=candidate\r\n", 600)}
	ada.must("call.signal", map[string]any{"call": st.Call.ID, "to": "bob", "type": "offer", "data": sdp}, nil)
	if got := field(bob.next("call.signal").Data, "data", "sdp").(string); len(got) != len(sdp["sdp"].(string)) {
		t.Fatalf("an offer arrived as %d bytes", len(got))
	}
}

func offerSDP(t *testing.T) string {
	t.Helper()
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	o, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetLocalDescription(o); err != nil {
		t.Fatal(err)
	}
	return pc.LocalDescription().SDP
}

func TestGroupCallPolicyOverTheSocket(t *testing.T) {
	s := start(t, nil)
	ada, bob := s.dial(s.acme, "ada"), s.dial(s.acme, "bob")
	var st startReply
	ada.must("call.start", map[string]any{"to": []string{"bob"}, "mode": "sfu"}, &st)
	id := st.Call.ID
	sdp := offerSDP(t)

	var ans map[string]any
	if err := ada.call("sfu.join", map[string]any{"call": id, "sdp": sdp}, &ans); code(err) != "e2ee_required" {
		t.Fatalf("a join without encryption: %v", err)
	}
	if err := ada.call("sfu.join", map[string]any{"call": id, "sdp": sdp, "e2ee": true}, &ans); err != nil || ans["e2ee"] != true || ans["sdp"] == "" {
		t.Fatalf("an encrypted join: %v %v", ans, err)
	}
	if err := bob.call("sfu.join", map[string]any{"call": id, "sdp": offerSDP(t), "e2ee": true}, nil); code(err) != "answer_the_call_first" {
		t.Fatalf("joining before answering: %v", err)
	}
	if err := ada.call("sfu.record.start", map[string]any{"call": id}, nil); code(err) != "recording_unavailable_e2ee" {
		t.Fatalf("recording an encrypted call: %v", err)
	}
	var stats map[string]any
	if err := ada.call("sfu.stats", map[string]any{"call": id}, &stats); err != nil || stats["e2ee"] != true {
		t.Fatalf("stats: %v %v", stats, err)
	}
	svcStats, _ := s.acme.Stats(bg)
	if svcStats["rooms"] != 1 || svcStats["peers"] != 1 || svcStats["connections"] != 2 {
		t.Fatalf("service stats: %v", svcStats)
	}
	ada.must("call.end", map[string]any{"call": id}, nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m, _ := s.acme.Stats(bg); m["rooms"] == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if m, _ := s.acme.Stats(bg); m["rooms"] != 0 {
		t.Fatal("the room outlived the call")
	}
	if err := ada.call("sfu.stats", map[string]any{"call": id}, nil); code(err) != "call_ended" {
		t.Fatalf("a call that ended: %v", err)
	}
}

func TestConfigurationMistakesAreRefusedAtStartup(t *testing.T) {
	db, _ := sql.Open("sqlite", "file::memory:")
	defer db.Close()
	good := server.Config{DB: db, Dialect: "sqlite", TokenSecret: "token-secret-token-secret-0123456", Keys: []auth.ServiceKey{{Name: "a", Key: acmeKey, Tenant: "acme"}}}
	mut := map[string]func(*server.Config){
		"no database":     func(c *server.Config) { c.DB = nil },
		"no keys":         func(c *server.Config) { c.Keys = nil },
		"short secret":    func(c *server.Config) { c.TokenSecret = "short" },
		"TURN no secret":  func(c *server.Config) { c.TURN = []string{"turn:t.example.com"} },
		"one udp bound":   func(c *server.Config) { c.UDPPortMin = 4000 },
		"bad record mode": func(c *server.Config) { c.RecordLayer = "middle" },
	}
	for name, f := range mut {
		c := good
		f(&c)
		if s, err := server.New(bg, c); err == nil {
			s.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// auditHold takes the audit database's write lock until the returned function
// is called.
func auditHold(t *testing.T, s *svc) func() {
	t.Helper()
	c, err := s.adb.Conn(bg) // the pool has one connection: while it is held, the audit writer cannot commit
	if err != nil {
		t.Fatal(err)
	}
	return func() { _ = c.Close() }
}

// startB is start for benchmarks.
func startB(b *testing.B, tweak func(*server.Config)) *svc {
	b.Helper()
	return startTB(b, tweak)
}

func clientStart(to string) client.StartRequest {
	return client.StartRequest{To: []string{to}, Mode: "sfu"}
}

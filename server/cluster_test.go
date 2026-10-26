package server_test

import (
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/client"
	"github.com/oarkflow/rtcd/server"
)

// node starts one rtcd node on a database shared with the others in dir.
func node(t *testing.T, dir, id string) *svc {
	t.Helper()
	open := func(name string) *sql.DB { return testDB(t, dir, name, 1) }
	cfg := server.Config{
		DB: open("shared.db"), AuditDB: open("audit-" + id + ".db"), Dialect: dialect(), NodeID: id,
		TokenSecret: "token-secret-token-secret-0123456", AllowedOrigins: []string{origin},
		Keys: []auth.ServiceKey{{Name: "chat", Key: acmeKey, Tenant: "acme"}},
	}
	s, err := server.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	app := fh.NewFast()
	s.Mount(app)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ln) }()
	stop := func() { _ = app.ShutdownWithTimeout(time.Second); _ = ln.Close(); _ = s.Close() }
	t.Cleanup(stop)
	base := "http://" + ln.Addr().String()
	return &svc{t: t, base: base, acme: client.New(base, acmeKey), srv: s}
}

func TestTwoNodesShareEventsTicketsAndRevocations(t *testing.T) {
	dir := t.TempDir()
	n1, n2 := node(t, dir, "n1"), node(t, dir, "n2")
	ada, bob := n1.dial(n1.acme, "ada"), n2.dial(n2.acme, "bob")

	// A group made on one node reaches a member connected to the other.
	g := group(t, ada, "bob")
	bob.next("group.added")
	// Messages cross nodes both ways, and membership is checked on the node that receives.
	ada.must("msg.send", map[string]any{"conv": g, "id": "1", "body": "c1"}, nil)
	if field(bob.next("msg.new").Data, "body") != "c1" {
		t.Fatal("body")
	}
	bob.must("msg.send", map[string]any{"conv": g, "id": "1", "body": "c2"}, nil)
	ada.next("msg.new") // her own, number 1
	if m := ada.next("msg.new"); field(m.Data, "seq") != float64(2) || field(m.Data, "body") != "c2" {
		t.Fatalf("numbering across nodes: %s", m.Data)
	}
	ada.must("group.remove", map[string]any{"group": g, "users": []string{"bob"}}, nil)
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := bob.call("msg.send", map[string]any{"conv": g, "id": "2", "body": "x"}, nil)
		if code(err) == "forbidden" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a member removed on node 1 can still send on node 2: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// A ticket from node 1 opens a connection on node 2, once.
	code1, body := n1.api(n1.token("cy"), "POST", "/v1/ws/ticket", []byte("{}"), nil)
	if code1 != 200 {
		t.Fatalf("ticket %d", code1)
	}
	tk := field(body, "ticket").(string)
	c, err := wsDial("ws" + n2.base[4:] + "/v1/ws?ticket=" + tk)
	if err != nil {
		t.Fatalf("a ticket on the other node: %v", err)
	}
	c.Close()
	if c, err := wsDial("ws" + n1.base[4:] + "/v1/ws?ticket=" + tk); err == nil {
		c.Close()
		t.Fatal("a ticket worked on both nodes")
	}

	// Revoke on node 1: node 2 closes the connection and refuses the old token.
	oldTok := n2.token("bob")
	if c, _ := n1.api(acmeKey, "POST", "/v1/tokens/revoke", []byte(`{"user":"bob"}`), nil); c != 200 {
		t.Fatalf("revoke %d", c)
	}
	select {
	case <-bob.Done():
	case <-time.After(6 * time.Second):
		t.Fatal("node 2 kept a revoked user")
	}
	if c, _ := n2.api(oldTok, "POST", "/v1/ice", []byte("{}"), nil); c != 401 {
		t.Fatalf("revoked token on node 2: %d", c)
	}

	// A node that starts later knows about it too.
	n3 := node(t, dir, "n3")
	if c, _ := n3.api(oldTok, "POST", "/v1/ice", []byte("{}"), nil); c != 401 {
		t.Fatalf("revoked token after a restart: %d", c)
	}
}

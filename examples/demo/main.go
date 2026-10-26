// Command demo runs rtcd with a browser example on top of it: sign in as any
// name, chat in end-to-end encrypted groups, send encrypted attachments, make
// group video calls, and run a self-test that checks the service from the
// browser. Open two windows with two names to see both sides.
//
//	go run ./examples/demo
//	go run ./examples/demo -db postgres -dsn 'postgres://user:pw@localhost/rtcd'
//
// This is a demonstration. A real application authenticates its own users and
// calls rtcd from its backend with a service key; here /demo/login hands a token
// to anyone who asks, which is exactly what a production backend must not do.
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/client"
	"github.com/oarkflow/rtcd/dbx/open"
	"github.com/oarkflow/rtcd/server"
	"github.com/oarkflow/rtcd/web"
)

//go:embed ui
var ui embed.FS

var userName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

func main() {
	addr := flag.String("addr", "127.0.0.1:8480", "listen address")
	driver := flag.String("db", "sqlite", "database: sqlite, postgres or mysql")
	dsn := flag.String("dsn", "", "database DSN (default: a SQLite file in -data)")
	data := flag.String("data", "", "directory for the database and attachments (default: a temporary one)")
	node := flag.String("node", "", "node id, to run several demo nodes on one database")
	flag.Parse()
	if err := run(*addr, *driver, *dsn, *data, *node); err != nil {
		log.Fatalf("demo: %v", err)
	}
}

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func run(addr, driver, dsn, data, node string) error {
	if data == "" {
		d, err := os.MkdirTemp("", "rtcd-demo-")
		if err != nil {
			return err
		}
		data = d
		defer os.RemoveAll(d)
	}
	if driver == "sqlite" && dsn == "" {
		dsn = "file:" + filepath.Join(data, "rtcd.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, dialect, err := open.DB(driver, dsn, open.Pool{})
	if err != nil {
		return err
	}
	defer db.Close()
	key := "demo-" + rnd(16)
	cfg := server.Config{
		DB: db, Dialect: dialect, NodeID: node,
		Keys:        []auth.ServiceKey{{Name: "demo", Key: key, Tenant: "demo"}},
		TokenSecret: "demo-" + rnd(24), MaxTokenTTL: time.Hour,
		AttachDir: filepath.Join(data, "files"),
		// Anyone can reach this page, so the demo keeps people apart and bounded.
		MaxFileBytes: 64 << 20, TenantFileBytes: 1 << 30, FileRetention: 24 * time.Hour, MsgRetention: 7 * 24 * time.Hour,
	}
	srv, err := server.New(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	base := "http://" + ln.Addr().String()
	svc := client.New(base, key)

	app := fh.NewFast(fh.WithReadHeaderTimeout(10*time.Second), fh.WithIdleTimeout(2*time.Minute), fh.WithMaxRequestBodySize(8<<20))
	srv.Mount(app)

	app.Post("/demo/login", func(c fh.Ctx) error {
		var in struct {
			User string `json:"user"`
		}
		if json.Unmarshal(c.Body(), &in) != nil || !userName.MatchString(in.User) {
			return c.Status(400).JSON(map[string]any{"error": map[string]string{"code": "invalid", "message": "use 1-32 letters, digits, dot, dash or underscore"}})
		}
		tok, err := svc.Token(c.Context(), in.User, 15*time.Minute)
		if err != nil {
			return c.Status(502).JSON(map[string]any{"error": map[string]string{"code": "backend", "message": err.Error()}})
		}
		return c.JSON(map[string]any{"token": tok.Token, "expires_at": tok.ExpiresAt.UTC().Format(time.RFC3339), "user": tok.User, "tenant": tok.Tenant})
	})
	// Revoking is something only a backend may do; the demo exposes it so the
	// self-test can check it.
	app.Post("/demo/revoke", func(c fh.Ctx) error {
		var in struct {
			User string `json:"user"`
		}
		if json.Unmarshal(c.Body(), &in) != nil || !userName.MatchString(in.User) {
			return c.Status(400).JSON(map[string]string{"error": "invalid"})
		}
		req, _ := http.NewRequestWithContext(c.Context(), "POST", base+"/v1/tokens/revoke", strings.NewReader(fmt.Sprintf(`{"user":%q}`, in.User)))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return c.Status(502).JSON(map[string]string{"error": err.Error()})
		}
		res.Body.Close()
		return c.Status(res.StatusCode).JSON(map[string]bool{"ok": res.StatusCode == 200})
	})
	app.Get("/demo/info", func(c fh.Ctx) error {
		st := srv.Stats()
		return c.JSON(map[string]any{
			"database": dialect, "node": node, "connections": st.Connections, "rooms": st.Rooms, "peers": st.Peers,
			"ops_ok": st.OpsOK, "ops_failed": st.OpsFailed, "ops_denied": st.OpsDenied,
			"events_sent": st.EventsSent, "events_dropped": st.EventsDropped, "slow_clients": st.SlowClientsDisconnected,
			"audit_queued": st.Audit.Queued, "audit_written": st.Audit.Written, "audit_refused": st.AuditRefused,
		})
	})

	serve := func(name, ctype string, fsys embed.FS, path string) {
		b, err := fsys.ReadFile(path)
		if err != nil {
			log.Fatalf("demo: embedded %s: %v", path, err)
		}
		app.Get(name, func(c fh.Ctx) error {
			c.Set("Content-Type", ctype)
			c.Set("Cache-Control", "no-cache")
			c.Set("X-Content-Type-Options", "nosniff")
			c.Set("Referrer-Policy", "no-referrer")
			if ctype[:9] == "text/html" {
				// Everything runs from this origin; nothing is fetched from elsewhere.
				c.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' blob: data:; media-src 'self' blob:; worker-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
				c.Set("Permissions-Policy", "camera=(self), microphone=(self)")
			}
			return c.Send(b)
		})
	}
	serve("/", "text/html; charset=utf-8", ui, "ui/index.html")
	for _, f := range []string{"app.css", "rtc.js", "chat.js", "call.js", "selftest.js", "app.js"} {
		ct := "text/javascript; charset=utf-8"
		if strings.HasSuffix(f, ".css") {
			ct = "text/css; charset=utf-8"
		}
		serve("/"+f, ct, ui, "ui/"+f)
	}
	serve("/favicon.svg", "image/svg+xml", ui, "ui/favicon.svg")
	for _, f := range []string{"e2ee-core.js", "e2ee-worker.js", "chat-core.js"} {
		serve("/"+f, "text/javascript; charset=utf-8", web.Files, f)
	}

	fmt.Printf("\n  rtcd demo  ->  %s\n  database: %s%s\n  Open it in two browser windows with two different names.\n\n", base, dialect, map[bool]string{true: ", node " + node, false: ""}[node != ""])
	errc := make(chan error, 1)
	go func() { errc <- app.Serve(ln) }()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-stop:
		return app.ShutdownWithTimeout(5 * time.Second)
	}
}

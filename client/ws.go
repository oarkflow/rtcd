package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

// Event is something the service pushed.
type Event struct {
	Name string
	Data json.RawMessage
	From string
}

// DialOptions tune Dial.
type DialOptions struct {
	// Origin is sent as the Origin header; the service checks it against its
	// allowed origins. Default http://localhost.
	Origin string
}

// Conn is a WebSocket connection to the service. It carries requests and the
// events the service pushes, and is safe for concurrent use.
type Conn struct {
	ws      *websocket.Conn
	wmu     sync.Mutex
	mu      sync.Mutex
	pending map[string]chan reply
	events  chan Event
	done    chan struct{}
	once    sync.Once
	err     error
	seq     atomic.Uint64
	dropped atomic.Int64
	ready   Event
}

type reply struct {
	payload json.RawMessage
	err     error
}

// Dial opens a WebSocket as this user. The first event, "ready", is already
// consumed; see Ready.
func (u *User) Dial(ctx context.Context, opts ...DialOptions) (*Conn, error) {
	var o DialOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.Origin == "" {
		o.Origin = "http://localhost"
	}
	base, err := url.Parse(u.c.base)
	if err != nil {
		return nil, err
	}
	switch base.Scheme {
	case "https":
		base.Scheme = "wss"
	default:
		base.Scheme = "ws"
	}
	base.Path = "/v1/ws"
	hdr := http.Header{}
	if u.user != "" { // a service key acting as a user
		hdr.Set("Authorization", "Bearer "+u.c.key)
		hdr.Set("X-RTC-User", u.user)
	} else {
		q := base.Query()
		q.Set("token", u.c.key)
		base.RawQuery = q.Encode()
	}
	cfg, err := websocket.NewConfig(base.String(), o.Origin)
	if err != nil {
		return nil, err
	}
	cfg.Header = hdr
	type dialed struct {
		c   *websocket.Conn
		err error
	}
	ch := make(chan dialed, 1)
	go func() { c, err := cfg.DialContext(ctx); ch <- dialed{c, err} }()
	var wsConn *websocket.Conn
	select {
	case d := <-ch:
		if d.err != nil {
			return nil, d.err
		}
		wsConn = d.c
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	wsConn.MaxPayloadBytes = 1 << 20
	c := &Conn{ws: wsConn, pending: map[string]chan reply{}, events: make(chan Event, 1024), done: make(chan struct{})}
	go c.read()
	go c.keepAlive()
	select {
	case ev, ok := <-c.events:
		if !ok || ev.Name != "ready" {
			c.Close()
			return nil, errors.New("rtcd: the service did not say ready")
		}
		c.ready = ev
	case <-time.After(10 * time.Second):
		c.Close()
		return nil, errors.New("rtcd: no ready event")
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
	return c, nil
}

// Ready is the service's first message: who you are and when your token ends.
func (c *Conn) Ready() Event { return c.ready }

// Events delivers what the service pushes. It is closed when the connection is.
func (c *Conn) Events() <-chan Event { return c.events }

// Dropped counts events thrown away because Events was not being read.
func (c *Conn) Dropped() int64 { return c.dropped.Load() }

// Done is closed when the connection ends; Err says why.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err is why the connection ended, or nil while it is open.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close ends the connection.
func (c *Conn) Close() { c.fail(errors.New("closed")) }

func (c *Conn) fail(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		for id, ch := range c.pending {
			ch <- reply{err: err}
			delete(c.pending, id)
		}
		c.mu.Unlock()
		_ = c.ws.Close()
		close(c.done)
		close(c.events)
	})
}

type wireIn struct {
	Type    string          `json:"type"`
	ReplyTo string          `json:"replyTo"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	From    string          `json:"from"`
	Code    string          `json:"code"`
	Error   string          `json:"error"`
}

func (c *Conn) read() {
	for {
		var msg string
		if err := websocket.Message.Receive(c.ws, &msg); err != nil {
			c.fail(err)
			return
		}
		var m wireIn
		if json.Unmarshal([]byte(msg), &m) != nil {
			continue
		}
		switch m.Type {
		case "ack", "error":
			c.mu.Lock()
			ch := c.pending[m.ReplyTo]
			delete(c.pending, m.ReplyTo)
			c.mu.Unlock()
			if ch == nil {
				continue
			}
			if m.Type == "error" {
				ch <- reply{err: wireError(m.Error)}
			} else {
				ch <- reply{payload: m.Payload}
			}
		case "emit":
			select {
			case c.events <- Event{Name: m.Event, Data: m.Payload, From: m.From}:
			default:
				c.dropped.Add(1)
			}
		}
	}
}

func (c *Conn) keepAlive() {
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.wmu.Lock()
			err := websocket.Message.Send(c.ws, `{"type":"ping"}`)
			c.wmu.Unlock()
			if err != nil {
				c.fail(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

// Call runs an operation (call.start, sfu.join, group.create, ...) and decodes
// the answer into out. Requests on one connection are answered in order.
func (c *Conn) Call(ctx context.Context, op string, in, out any) error {
	payload := json.RawMessage("{}")
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		payload = b
	}
	id := strconv.FormatUint(c.seq.Add(1), 36)
	req, _ := json.Marshal(map[string]any{"type": "emit", "id": id, "event": op, "payload": payload})
	ch := make(chan reply, 1)
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.pending[id] = ch
	c.mu.Unlock()
	c.wmu.Lock()
	err := websocket.Message.Send(c.ws, string(req))
	c.wmu.Unlock()
	if err != nil {
		c.fail(err)
		return err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if out != nil && len(r.payload) > 0 {
			return json.Unmarshal(r.payload, out)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// wireError turns "code" or "code: message" into an *Error.
func wireError(s string) error {
	code, msg, _ := strings.Cut(s, ": ")
	return &Error{Status: statusOf(code), Code: code, Message: msg}
}

func statusOf(code string) int {
	switch code {
	case "forbidden", "scope_missing", "service_key_required", "only_the_caller_can_record", "device_revoked", "too_late":
		return 403
	case "unauthenticated", "token_expired":
		return 401
	case "invalid", "e2ee_required", "bad_preferences", "user_required":
		return 400
	case "not_found":
		return 404
	case "call_ended":
		return 410
	case "rate_limited", "room_full", "limit_reached", "too_many_connections":
		return 429
	case "stale_epoch", "rekey_required", "conflict", "id_taken", "members_without_keys":
		return 409
	case "call_not_active", "negotiating", "not_in_room", "answer_the_call_first", "already_recording",
		"not_recording", "recording_unavailable_e2ee", "no_offer_outstanding":
		return 409
	}
	return 503
}

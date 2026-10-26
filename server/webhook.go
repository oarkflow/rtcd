package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"
)

// The webhook tells the backend about what it must act on while a user may not
// be connected: a message to push a notification for, a conversation that needs
// a new key. It carries identifiers and sizes, never message contents (the
// service has none to give).
//
// Events are batched, signed, and retried with growing waits. They are held in
// memory: a node that stops loses what it had not delivered. That is safe
// because nothing depends on a webhook arriving: a client catches up from
// msg.history when it connects, and a push is a hint to do so.
//
//	POST <webhook_url>
//	X-RTC-Timestamp: <unix seconds>
//	X-RTC-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>
//	{"events":[{"id":"…","type":"msg.new","tenant":"acme","conv":"…","seq":7,…}]}
//
// The backend should check the signature and that the timestamp is recent, and
// may use "id" to ignore a delivery it has already handled.

// HookEvent is one webhook event.
type HookEvent struct {
	ID     string `json:"id"`
	Type   string `json:"type"` // msg.new, msg.deleted, conv.rekey, key.added, key.revoked
	Tenant string `json:"tenant"`
	At     int64  `json:"at"` // unix milliseconds
	Conv   string `json:"conv,omitempty"`
	Seq    int64  `json:"seq,omitempty"`
	Msg    string `json:"msg,omitempty"` // the sender's id for the message
	Sender string `json:"sender,omitempty"`
	// Recipients is everyone in the conversation but the sender. Connected is
	// those of them with a live connection to the node that handled the message;
	// in a cluster others may be connected elsewhere, so treat it as a hint.
	Recipients []string `json:"recipients,omitempty"`
	Connected  []string `json:"connected,omitempty"`
	Size       int      `json:"size,omitempty"`
	Epoch      int64    `json:"epoch,omitempty"`
	User       string   `json:"user,omitempty"`
	Device     string   `json:"device,omitempty"`
}

const (
	hookQueue    = 10000
	hookBatch    = 100
	hookFlush    = 200 * time.Millisecond
	hookAttempts = 6
)

type webhook struct {
	s       *Server
	url     string
	secret  []byte
	q       chan HookEvent
	done    chan struct{}
	stopped chan struct{}
	client  *http.Client

	sent, retried, dropped atomic.Int64
}

func newWebhook(s *Server, rawURL, secret string) (*webhook, error) {
	h := &webhook{s: s}
	if rawURL == "" {
		return h, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("rtcd: webhook_url must be an http(s) URL")
	}
	if len(secret) < 16 {
		return nil, errors.New("rtcd: webhook_secret (at least 16 characters) is required with webhook_url")
	}
	h.url, h.secret = rawURL, []byte(secret)
	h.q = make(chan HookEvent, hookQueue)
	h.done, h.stopped = make(chan struct{}), make(chan struct{})
	h.client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go h.run()
	return h, nil
}

func (h *webhook) enabled() bool { return h != nil && h.q != nil }

func (h *webhook) close() {
	if !h.enabled() {
		return
	}
	select {
	case <-h.done:
		return
	default:
		close(h.done)
	}
	select {
	case <-h.stopped:
	case <-time.After(3 * time.Second):
	}
}

// emit queues an event. It never blocks: a full queue drops the event.
func (h *webhook) emit(e HookEvent) {
	if !h.enabled() {
		return
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	e.ID = hex.EncodeToString(id[:])
	e.At = h.s.cfg.Now().UnixMilli()
	select {
	case h.q <- e:
	default:
		h.dropped.Add(1)
	}
}

func (h *webhook) run() {
	defer close(h.stopped)
	t := time.NewTimer(time.Hour)
	t.Stop()
	var batch []HookEvent
	flush := func() {
		if len(batch) > 0 {
			h.deliver(batch)
			batch = nil
		}
	}
	for {
		select {
		case e := <-h.q:
			if len(batch) == 0 {
				t.Reset(hookFlush)
			}
			batch = append(batch, e)
			if len(batch) >= hookBatch {
				t.Stop()
				flush()
			}
		case <-t.C:
			flush()
		case <-h.done:
			// Drain what is already queued, once, without retrying for long.
			for {
				select {
				case e := <-h.q:
					batch = append(batch, e)
					continue
				default:
				}
				break
			}
			if len(batch) > 0 {
				_ = h.post(batch)
			}
			return
		}
	}
}

func (h *webhook) post(batch []HookEvent) error {
	body, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(h.s.cfg.Now().Unix(), 10)
	req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rtcd-webhook")
	req.Header.Set("X-RTC-Timestamp", ts)
	req.Header.Set("X-RTC-Signature", "v1="+Sign(h.secret, ts, body))
	res, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("webhook answered %d", res.StatusCode)
	}
	return nil
}

func (h *webhook) deliver(batch []HookEvent) {
	wait := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		if err := h.post(batch); err == nil {
			h.sent.Add(int64(len(batch)))
			return
		}
		if attempt >= hookAttempts {
			h.dropped.Add(int64(len(batch)))
			return
		}
		h.retried.Add(1)
		select {
		case <-time.After(wait):
		case <-h.done:
			h.dropped.Add(int64(len(batch)))
			return
		}
		wait *= 2
	}
}

// Sign returns the hex signature a webhook carries: HMAC-SHA256 of
// timestamp + "." + body. A backend verifies a delivery by computing the same.
func Sign(secret []byte, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp))
	m.Write([]byte{'.'})
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

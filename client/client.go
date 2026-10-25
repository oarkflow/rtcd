// Package client is the Go client of the call service.
//
// A backend holds a service key and acts for its users:
//
//	svc := client.New("https://calls.example.com", key)
//	call, err := svc.As("ada").Start(ctx, client.StartRequest{To: []string{"bob"}, Mode: "sfu"})
//	tok, err := svc.Token(ctx, "bob", 10*time.Minute) // hand this to bob's browser
//
// A program that holds a user's token (a test, a bot) uses NewUser.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Error is an error answer from the service.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("rtcd: %s (%d): %s", e.Code, e.Status, e.Message)
	}
	return fmt.Sprintf("rtcd: %s (%d)", e.Code, e.Status)
}

// Is lets errors.Is match the common cases by status.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrForbidden:
		return e.Status == 403
	case ErrUnauthenticated:
		return e.Status == 401
	case ErrInvalid:
		return e.Status == 400
	case ErrConflict:
		return e.Status == 409 || e.Status == 410
	}
	return false
}

// Sentinels for errors.Is.
var (
	ErrForbidden       = errors.New("rtcd: forbidden")
	ErrUnauthenticated = errors.New("rtcd: unauthenticated")
	ErrInvalid         = errors.New("rtcd: invalid request")
	ErrConflict        = errors.New("rtcd: conflict")
)

// Participant is one person in a call.
type Participant struct {
	User  string `json:"user"`
	State string `json:"state"` // invited, joined, declined, left
}

// Call is a call and its participants.
type Call struct {
	ID           string        `json:"id"`
	Kind         string        `json:"kind"`
	Mode         string        `json:"mode"`
	Initiator    string        `json:"initiator"`
	Status       string        `json:"status"` // ringing, active, ended
	Reason       string        `json:"reason,omitempty"`
	E2EE         bool          `json:"e2ee"`
	Group        string        `json:"group,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	AnsweredAt   *time.Time    `json:"answered_at,omitempty"`
	EndedAt      *time.Time    `json:"ended_at,omitempty"`
	Participants []Participant `json:"participants"`
}

// ICEServer is a STUN or TURN server for a peer connection.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// StartRequest places a call. Kind is audio or video (default video), Mode is
// p2p for two people or sfu for a group (default p2p). E2EE nil takes the
// service's policy; a service that requires encryption refuses false.
type StartRequest struct {
	To   []string `json:"to"`
	Kind string   `json:"kind,omitempty"`
	Mode string   `json:"mode,omitempty"`
	E2EE *bool    `json:"e2ee,omitempty"`
}

// CallWithICE is a call and the ICE servers its caller should use.
type CallWithICE struct {
	Call Call        `json:"call"`
	ICE  []ICEServer `json:"ice"`
}

// Token is a credential for one user, safe to give to a browser.
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      string    `json:"user"`
	Tenant    string    `json:"tenant"`
}

// Client is a backend service's connection to the call service.
type Client struct {
	base string
	key  string
	HTTP *http.Client
}

// New makes a Client for a backend service. baseURL is the service's root.
func New(baseURL, serviceKey string) *Client {
	return &Client{base: strings.TrimRight(baseURL, "/"), key: serviceKey, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// BaseURL is the service's root.
func (c *Client) BaseURL() string { return c.base }

// Token mints a short-lived token for a user of this service key's tenant. With
// no scopes it can use calls and groups; pass "calls" or "groups" to narrow it.
func (c *Client) Token(ctx context.Context, user string, ttl time.Duration, scopes ...string) (Token, error) {
	var out Token
	err := c.do(ctx, "POST", "/v1/tokens", "", map[string]any{"user": user, "ttl_seconds": int(ttl.Seconds()), "scopes": scopes}, &out)
	return out, err
}

// AuditFilter selects audit entries. Action ending in "." matches a prefix.
type AuditFilter struct {
	Actor    string    `json:"actor,omitempty"`
	Action   string    `json:"action,omitempty"`
	Target   string    `json:"target,omitempty"`
	Outcome  string    `json:"outcome,omitempty"`
	From     time.Time `json:"from,omitempty"`
	To       time.Time `json:"to,omitempty"`
	AfterSeq uint64    `json:"after_seq,omitempty"`
	Limit    int       `json:"limit,omitempty"`
	Newest   bool      `json:"newest,omitempty"`
}

// AuditEvent is one audit entry.
type AuditEvent struct {
	Seq       uint64         `json:"seq"`
	Time      time.Time      `json:"time"`
	Actor     string         `json:"actor"`
	Service   string         `json:"service"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Outcome   string         `json:"outcome"`
	Code      string         `json:"code"`
	IP        string         `json:"ip"`
	Transport string         `json:"transport"`
	Conn      string         `json:"conn"`
	Meta      map[string]any `json:"meta"`
	Prev      string         `json:"prev"`
	Hash      string         `json:"hash"`
}

// Audit reads this tenant's audit log (service key only).
func (c *Client) Audit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	var out struct {
		Events []AuditEvent `json:"events"`
	}
	err := c.do(ctx, "POST", "/v1/audit/query", "", f, &out)
	return out.Events, err
}

// AuditVerification is the result of checking the audit chain.
type AuditVerification struct {
	Verification struct {
		Checked uint64 `json:"checked"`
		LastSeq uint64 `json:"last_seq"`
		OK      bool   `json:"ok"`
		BadSeq  uint64 `json:"bad_seq"`
		Reason  string `json:"reason"`
	} `json:"verification"`
	HeadSeq  uint64 `json:"head_seq"`
	HeadHash string `json:"head_hash"`
}

// VerifyAudit checks that this tenant's audit entries have not been altered.
// Keep HeadHash somewhere safe: entries cut off the end cannot be noticed
// from inside.
func (c *Client) VerifyAudit(ctx context.Context, afterSeq uint64) (AuditVerification, error) {
	var out AuditVerification
	err := c.do(ctx, "POST", "/v1/audit/verify", "", map[string]any{"after_seq": afterSeq}, &out)
	return out, err
}

// Stats reports what the service is carrying (service key only).
func (c *Client) Stats(ctx context.Context) (map[string]int64, error) {
	var out map[string]int64
	err := c.do(ctx, "GET", "/v1/stats", "", nil, &out)
	return out, err
}

// As returns a view of the service that acts as one user.
func (c *Client) As(user string) *User { return &User{c: c, user: user} }

// NewUser makes a User from a token, for a program that is the end user.
func NewUser(baseURL, token string) *User {
	return &User{c: &Client{base: strings.TrimRight(baseURL, "/"), key: token, HTTP: &http.Client{Timeout: 15 * time.Second}}}
}

// User is a call service connection that acts as one user.
type User struct {
	c    *Client
	user string // set when a service key acts as the user; empty for a token
}

func (u *User) do(ctx context.Context, method, path string, in, out any) error {
	return u.c.do(ctx, method, path, u.user, in, out)
}

// Do calls any operation by name over HTTP and decodes the answer into out. It
// is how groups and anything newer than this client are used.
func (u *User) Do(ctx context.Context, op string, in, out any) error {
	method, path := "POST", "/v1/"+strings.ReplaceAll(op, ".", "/")
	for _, r := range opRoutes {
		if r.op == op {
			method, path = r.method, r.path
			if r.idField != "" {
				m := map[string]any{}
				if b, err := json.Marshal(in); err == nil {
					_ = json.Unmarshal(b, &m)
				}
				id, _ := m[r.idField].(string)
				path = strings.Replace(path, ":id", url.PathEscape(id), 1)
				delete(m, r.idField)
				in = m
			}
			break
		}
	}
	if method == "GET" {
		in = nil
	}
	return u.do(ctx, method, path, in, out)
}

type opRoute struct{ method, path, op, idField string }

var opRoutes = func() []opRoute {
	r := []opRoute{
		{"POST", "/v1/ice", "ice", ""}, {"POST", "/v1/calls", "call.start", ""}, {"GET", "/v1/calls/:id", "call.get", "call"},
		{"POST", "/v1/groups", "group.create", ""}, {"GET", "/v1/groups", "group.list", ""}, {"GET", "/v1/groups/:id", "group.get", "group"},
	}
	for _, a := range []string{"answer", "decline", "end", "invite", "signal", "e2ee"} {
		r = append(r, opRoute{"POST", "/v1/calls/:id/" + a, "call." + a, "call"})
	}
	for _, a := range []string{"join", "answer", "candidate", "leave", "ready", "restart", "resync", "prefs", "stats", "sample", "record/start", "record/stop", "record/status"} {
		r = append(r, opRoute{"POST", "/v1/calls/:id/sfu/" + a, "sfu." + strings.ReplaceAll(a, "/", "."), "call"})
	}
	for _, a := range []string{"rename", "add", "remove", "role", "transfer", "delete", "call"} {
		r = append(r, opRoute{"POST", "/v1/groups/:id/" + a, "group." + a, "group"})
	}
	return r
}()

// Start places a call and rings the people invited.
func (u *User) Start(ctx context.Context, r StartRequest) (CallWithICE, error) {
	var out CallWithICE
	return out, u.do(ctx, "POST", "/v1/calls", r, &out)
}

// Get reads a call the user takes part in.
func (u *User) Get(ctx context.Context, id string) (Call, error) {
	var out Call
	return out, u.do(ctx, "GET", "/v1/calls/"+url.PathEscape(id), nil, &out)
}

// Answer accepts a call.
func (u *User) Answer(ctx context.Context, id string) (CallWithICE, error) {
	var out CallWithICE
	return out, u.do(ctx, "POST", "/v1/calls/"+url.PathEscape(id)+"/answer", nil, &out)
}

// Decline refuses a call.
func (u *User) Decline(ctx context.Context, id string) (Call, error) {
	var out Call
	return out, u.do(ctx, "POST", "/v1/calls/"+url.PathEscape(id)+"/decline", nil, &out)
}

// End hangs up: it cancels a ringing call and leaves or ends an active one.
func (u *User) End(ctx context.Context, id string) (Call, error) {
	var out Call
	return out, u.do(ctx, "POST", "/v1/calls/"+url.PathEscape(id)+"/end", nil, &out)
}

// Signal relays an SDP or ICE message to the other side of a p2p call.
func (u *User) Signal(ctx context.Context, id, to, typ string, data any) error {
	return u.do(ctx, "POST", "/v1/calls/"+url.PathEscape(id)+"/signal", map[string]any{"to": to, "type": typ, "data": data}, nil)
}

// E2EE relays an end-to-end encryption message (a key exchange) to another
// participant. The service carries it and cannot read it.
func (u *User) E2EE(ctx context.Context, id, to, data string) error {
	return u.do(ctx, "POST", "/v1/calls/"+url.PathEscape(id)+"/e2ee", map[string]any{"to": to, "data": data}, nil)
}

// ICE returns STUN/TURN servers with a short-lived TURN credential.
func (u *User) ICE(ctx context.Context) ([]ICEServer, error) {
	var out struct {
		ICE []ICEServer `json:"ice"`
	}
	err := u.do(ctx, "POST", "/v1/ice", nil, &out)
	return out.ICE, err
}

// SFU calls an SFU signaling operation by name ("join", "answer", "candidate",
// "leave", "ready", "restart", "resync", "prefs", "stats", "sample",
// "record/start", "record/stop", "record/status") and decodes the answer into out.
func (u *User) SFU(ctx context.Context, callID, op string, in, out any) error {
	return u.do(ctx, "POST", "/v1/calls/"+url.PathEscape(callID)+"/sfu/"+op, in, out)
}

// Invite adds people to a group call that is under way.
func (u *User) Invite(ctx context.Context, id string, users ...string) (Call, error) {
	var out Call
	return out, u.do(ctx, "POST", "/v1/calls/"+url.PathEscape(id)+"/invite", map[string]any{"users": users}, &out)
}

func (c *Client) do(ctx context.Context, method, path, actAs string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if actAs != "" {
		req.Header.Set("X-RTC-User", actAs)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error.Code == "" {
			e.Error.Code = http.StatusText(resp.StatusCode)
		}
		return &Error{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

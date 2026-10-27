package client

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ConvSpec describes a managed conversation: chat whose membership the backend
// decides. See the README's "Managed conversations". Durations are in seconds;
// nil leaves a setting as it is.
type ConvSpec struct {
	ID           string   `json:"id"`
	Members      []string `json:"members,omitempty"`
	Admins       []string `json:"admins,omitempty"`
	Retention    *int64   `json:"retention,omitempty"`
	DefaultTTL   *int64   `json:"default_ttl,omitempty"`
	DeleteWindow *int64   `json:"delete_window,omitempty"`
}

// ConvState is a conversation's key epoch and policy.
type ConvState struct {
	Epoch        int64 `json:"epoch"`
	RekeyNeeded  bool  `json:"rekey_required"`
	Retention    int64 `json:"retention,omitempty"`
	DefaultTTL   int64 `json:"default_ttl,omitempty"`
	DeleteWindow int64 `json:"delete_window,omitempty"`
}

// ConvReply is the answer to a managed-conversation call.
type ConvReply struct {
	Conv    string    `json:"conv"`
	Created bool      `json:"created,omitempty"`
	Added   []string  `json:"added,omitempty"`
	Removed []string  `json:"removed,omitempty"`
	State   ConvState `json:"state"`
	Members []struct {
		User string `json:"user"`
		Role string `json:"role"`
	} `json:"members,omitempty"`
}

func (c *Client) conv(ctx context.Context, op string, in any) (ConvReply, error) {
	var out ConvReply
	return out, c.do(ctx, http.MethodPost, "/v1/conversations/"+op, "", in, &out)
}

// OpenConv opens a managed conversation, or admits Members to it if it is open.
func (c *Client) OpenConv(ctx context.Context, s ConvSpec) (ConvReply, error) {
	return c.conv(ctx, "open", s)
}

// AdmitToConv lets users in; admins are made administrators.
func (c *Client) AdmitToConv(ctx context.Context, id string, members, admins []string) (ConvReply, error) {
	return c.conv(ctx, "admit", ConvSpec{ID: id, Members: members, Admins: admins})
}

// RemoveFromConv takes users out at once. The conversation then needs a new key epoch.
func (c *Client) RemoveFromConv(ctx context.Context, id string, users ...string) (ConvReply, error) {
	return c.conv(ctx, "remove", map[string]any{"id": id, "members": users})
}

// SetConvRole makes a member an "admin" or a "member".
func (c *Client) SetConvRole(ctx context.Context, id, user, role string) error {
	return c.do(ctx, http.MethodPost, "/v1/conversations/role", "", map[string]any{"id": id, "user": user, "role": role}, nil)
}

// CloseConv deletes a conversation with its messages, keys and files.
func (c *Client) CloseConv(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/conversations/close", "", map[string]any{"id": id}, nil)
}

// GetConv reads who is in a conversation and its key state.
func (c *Client) GetConv(ctx context.Context, id string) (ConvReply, error) {
	return c.conv(ctx, "get", map[string]any{"id": id})
}

// SetConvPolicy changes retention, default message lifetime and delete window.
func (c *Client) SetConvPolicy(ctx context.Context, s ConvSpec) (ConvReply, error) {
	return c.conv(ctx, "policy", s)
}

// RevokeDevice retires a user's device key (the backend's word is final: the
// device can never publish again, and its conversations require a new epoch).
func (c *Client) RevokeDevice(ctx context.Context, user, device string) error {
	return c.do(ctx, http.MethodPost, "/v1/keys/revoke", user, map[string]any{"device": device}, nil)
}

// VerifyWebhook checks a delivery from the service's webhook: the signature over
// timestamp + "." + body with the shared secret, and that the timestamp is
// within maxAge (use a minute or two). Pass the X-RTC-Timestamp and
// X-RTC-Signature headers and the raw body.
func VerifyWebhook(secret []byte, timestamp, signature string, body []byte, maxAge time.Duration, now time.Time) error {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("rtcd webhook: bad timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > maxAge || d < -maxAge {
		return errors.New("rtcd webhook: stale timestamp")
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp))
	m.Write([]byte{'.'})
	m.Write(body)
	want := hex.EncodeToString(m.Sum(nil))
	got := strings.TrimPrefix(signature, "v1=")
	if !hmac.Equal([]byte(got), []byte(want)) {
		return errors.New("rtcd webhook: bad signature")
	}
	return nil
}

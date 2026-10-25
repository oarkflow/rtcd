package client

import (
	"context"
	"net/http"
)

// RoomSpec describes a managed room: a call whose membership the backend
// decides. See the README's "Managed rooms".
type RoomSpec struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind,omitempty"` // audio or video
	E2EE    *bool    `json:"e2ee,omitempty"`
	Members []string `json:"members,omitempty"`
	// Limits for this room; zero takes the service's defaults.
	MaxPeers   int `json:"max_peers,omitempty"`
	LastNVideo int `json:"last_n_video,omitempty"`
	LastNAudio int `json:"last_n_audio,omitempty"`
}

// RoomReply is a managed room and, for RoomGet, who is connected to its media.
type RoomReply struct {
	Call      Call     `json:"call"`
	Connected []string `json:"connected,omitempty"`
}

// OpenRoom opens a managed room, or admits Members to it if it is already open.
func (c *Client) OpenRoom(ctx context.Context, r RoomSpec) (RoomReply, error) {
	var out RoomReply
	return out, c.do(ctx, http.MethodPost, "/v1/rooms/open", "", r, &out)
}

// AdmitToRoom lets users into a managed room.
func (c *Client) AdmitToRoom(ctx context.Context, id string, users ...string) (RoomReply, error) {
	var out RoomReply
	return out, c.do(ctx, http.MethodPost, "/v1/rooms/admit", "", map[string]any{"id": id, "members": users}, &out)
}

// RemoveFromRoom takes users out of a managed room and disconnects them.
func (c *Client) RemoveFromRoom(ctx context.Context, id string, users ...string) (RoomReply, error) {
	var out RoomReply
	return out, c.do(ctx, http.MethodPost, "/v1/rooms/remove", "", map[string]any{"id": id, "members": users}, &out)
}

// CloseRoom ends a managed room for everyone.
func (c *Client) CloseRoom(ctx context.Context, id string) (RoomReply, error) {
	var out RoomReply
	return out, c.do(ctx, http.MethodPost, "/v1/rooms/close", "", map[string]any{"id": id}, &out)
}

// RoomGet reads a managed room and who is connected to it.
func (c *Client) RoomGet(ctx context.Context, id string) (RoomReply, error) {
	var out RoomReply
	return out, c.do(ctx, http.MethodPost, "/v1/rooms/get", "", map[string]any{"id": id}, &out)
}

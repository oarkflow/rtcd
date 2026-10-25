package server_test

import (
	"fmt"
	"testing"

	"github.com/oarkflow/rtcd/client"
)

func manyUsers(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("u%03d", i)
	}
	return out
}

func TestAManagedRoomAdmitsWhomTheBackendNamesWithoutRinging(t *testing.T) {
	s := start(t, nil)
	members := manyUsers(60) // more than a call may invite
	r, err := s.acme.OpenRoom(bg, client.RoomSpec{ID: "room-1", Members: members})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Call.E2EE || r.Call.Mode != "sfu" || r.Call.Status != "active" {
		t.Fatalf("room: %+v", r.Call)
	}
	u0, u1 := s.dial(s.acme, "u000"), s.dial(s.acme, "u001")
	u1.none(100 * 1e6) // admission is not an invitation: nobody's phone rings

	// A member goes straight to the media, with no answering step.
	var ans map[string]any
	if err := u0.call("sfu.join", map[string]any{"call": "room-1", "sdp": offerSDP(t)}, &ans); code(err) != "e2ee_required" {
		t.Fatalf("a plain join: %v", err)
	}
	if err := u0.call("sfu.join", map[string]any{"call": "room-1", "sdp": offerSDP(t), "e2ee": true}, &ans); err != nil || ans["sdp"] == "" {
		t.Fatalf("a member's join: %v %v", ans, err)
	}

	// Someone who was not admitted gets the answer a stranger gets.
	out := s.dial(s.acme, "outsider")
	if err := out.call("sfu.join", map[string]any{"call": "room-1", "sdp": offerSDP(t), "e2ee": true}, nil); code(err) != "forbidden" {
		t.Fatalf("an outsider: %v", err)
	}
	// A member cannot end the room, however they try.
	u1.must("call.end", map[string]any{"call": "room-1"}, nil)
	if got, err := s.acme.RoomGet(bg, "room-1"); err != nil || got.Call.Status != "active" {
		t.Fatalf("a member ended the room: %+v %v", got.Call, err)
	}
	// Another tenant can neither see nor use the id.
	if _, err := s.zeta.RoomGet(bg, "room-1"); code(err) != "forbidden" {
		t.Fatalf("another tenant read the room: %v", err)
	}
	if _, err := s.zeta.OpenRoom(bg, client.RoomSpec{ID: "room-1", Members: []string{"x"}}); code(err) != "forbidden" {
		t.Fatalf("another tenant took the id: %v", err)
	}
	// Removal disconnects at once and shuts the door.
	if _, err := s.acme.RemoveFromRoom(bg, "room-1", "u000"); err != nil {
		t.Fatal(err)
	}
	u0.next("room.removed")
	if got, _ := s.acme.RoomGet(bg, "room-1"); len(got.Connected) != 0 {
		t.Fatalf("a removed user is still connected: %v", got.Connected)
	}
	if err := u0.call("sfu.join", map[string]any{"call": "room-1", "sdp": offerSDP(t), "e2ee": true}, nil); code(err) != "answer_the_call_first" && code(err) != "forbidden" {
		t.Fatalf("a removed user rejoined: %v", err)
	}
	// ...until the backend lets them back.
	if _, err := s.acme.AdmitToRoom(bg, "room-1", "u000"); err != nil {
		t.Fatal(err)
	}
	if err := u0.call("sfu.join", map[string]any{"call": "room-1", "sdp": offerSDP(t), "e2ee": true}, &ans); err != nil {
		t.Fatalf("an admitted user: %v", err)
	}
	// Only the backend ends it.
	if _, err := s.acme.CloseRoom(bg, "room-1"); err != nil {
		t.Fatal(err)
	}
	if err := u1.call("sfu.stats", map[string]any{"call": "room-1"}, nil); code(err) != "call_ended" {
		t.Fatalf("a closed room: %v", err)
	}
}

func TestAManagedRoomRefusesPlaintextAndUsersCannotOpenOne(t *testing.T) {
	s := start(t, nil)
	off := false
	if _, err := s.acme.OpenRoom(bg, client.RoomSpec{ID: "p", Members: []string{"a"}, E2EE: &off}); code(err) != "invalid" && err == nil {
		t.Fatalf("plaintext room: %v", err)
	}
	if _, err := s.acme.OpenRoom(bg, client.RoomSpec{ID: "bad id!", Members: []string{"a"}}); err == nil {
		t.Fatal("an id with spaces was accepted")
	}
	u := s.dial(s.acme, "u000")
	if err := u.call("room.open", map[string]any{"id": "mine", "members": []string{"u000"}}, nil); code(err) != "service_key_required" {
		t.Fatalf("a user opened a room: %v", err)
	}
}

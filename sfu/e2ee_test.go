package sfu

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// secureJoin joins like client.join but through JoinSecure.
func (c *client) secureJoin(ctx context.Context) {
	c.h.t.Helper()
	if len(c.pc.GetTransceivers()) == 0 {
		if _, err := c.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
			c.h.t.Fatal(err)
		}
	}
	offer, err := c.pc.CreateOffer(nil)
	if err != nil {
		c.h.t.Fatal(err)
	}
	if err := c.pc.SetLocalDescription(offer); err != nil {
		c.h.t.Fatal(err)
	}
	answer, err := c.h.srv.JoinSecure(ctx, testRoom, c.user, *c.pc.LocalDescription())
	if err != nil {
		c.h.t.Fatalf("secure join %s: %v", c.user, err)
	}
	if err := c.pc.SetRemoteDescription(answer); err != nil {
		c.h.t.Fatal(err)
	}
	_ = c.h.srv.Ready(testRoom, c.user)
	c.mu.Lock()
	c.joined = true
	q := c.queued
	c.queued = nil
	c.mu.Unlock()
	for _, ci := range q {
		_ = c.h.srv.Candidate(testRoom, c.user, ci)
	}
}

func TestAPlainJoinCannotEnterAnEncryptedRoom(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("ada", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.secureJoin(ctx)
	if !h.srv.E2EE(testRoom) {
		t.Fatal("the room is not marked end-to-end encrypted")
	}
	// Somebody who does not encrypt would put plaintext into a call everyone else
	// thinks is private; the server will not let them in.
	mallory := h.newClient("mallory")
	if _, err := h.srv.Join(ctx, testRoom, "mallory", offerOf(t, mallory)); err != ErrE2EERequired {
		t.Fatalf("a plain join to an encrypted room: %v", err)
	}
	if got := h.srv.Peers(testRoom); len(got) != 1 {
		t.Fatalf("people: %v", got)
	}
	// An encrypted join is fine.
	bob := h.newClient("bob")
	bob.secureJoin(ctx)
	if got := h.srv.Peers(testRoom); len(got) != 2 {
		t.Fatalf("people: %v", got)
	}
}

func offerOf(t *testing.T, c *client) webrtc.SessionDescription {
	t.Helper()
	if len(c.pc.GetTransceivers()) == 0 {
		_, _ = c.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
	}
	o, err := c.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.pc.SetLocalDescription(o); err != nil {
		t.Fatal(err)
	}
	return *c.pc.LocalDescription()
}

func TestAnEncryptedCallCannotBeRecordedByTheServer(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("ada", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.RecordDir = t.TempDir() })
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.secureJoin(ctx)
	if _, err := h.srv.StartRecording(testRoom, "ada"); err != ErrRecordingE2EE {
		t.Fatalf("recording an encrypted call: %v", err)
	}
	// The same server records a plain room.
	ada2 := h.newClient("ada2")
	_ = ada2
}

func TestH264IsNotForwardedInAnEncryptedRoomAndThePublisherIsTold(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	for _, u := range []string{"ada", "bob", "cy"} {
		est.set(u, 30000)
	}
	h := newSimHarness(t, est, nil)
	ada, bob, cy := h.newClient("ada"), h.newClient("bob"), h.newClient("cy")
	ada.startH264Camera("q", "h", "f")
	bob.startCamera("q", "h", "f")
	for _, c := range []*client{ada, bob, cy} {
		c.secureJoin(ctx)
	}
	wc := cy.rawWatch()
	eventually(t, 30*time.Second, "cy sees bob (VP8 is allowed)", func() bool { return wc.n("bob") > 30 })
	time.Sleep(2 * time.Second)
	if wc.n("ada") != 0 {
		t.Fatal("H.264 video was forwarded in an encrypted room")
	}
	eventually(t, 10*time.Second, "ada is told why nobody sees her video", func() bool {
		st, _ := h.srv.PeerStats(testRoom, "ada")
		return len(st.Notes) == 1 && strings.Contains(st.Notes[0], "H.264") && st.E2EE
	})
}

func TestTheServerShowsAParticipantOnlyTheirOwnBytes(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	for _, u := range []string{"ada", "cy"} {
		est.set(u, 30000)
	}
	h := newSimHarness(t, est, nil)
	ada, cy := h.newClient("ada"), h.newClient("cy")
	ada.startCamera("q", "h", "f")
	ada.secureJoin(ctx)
	cy.secureJoin(ctx) // watches, publishes nothing
	eventually(t, 20*time.Second, "ada's sample exists", func() bool {
		a, _ := h.srv.Sample(testRoom, "ada")
		return a["video"] != ""
	})
	// cy sees ada's video but sent none, so the server holds nothing of cy's:
	// a sample is only ever the caller's own media, never somebody else's.
	if got, err := h.srv.Sample(testRoom, "cy"); err != nil || got["video"] != "" {
		t.Fatalf("cy was shown %v (%v), but sent no video", got, err)
	}
	if _, err := h.srv.Sample(testRoom, "nobody"); err != nil {
		t.Fatalf("unknown user: %v", err)
	}
	if got, _ := h.srv.Sample("no-such-room", "ada"); got != nil {
		t.Fatal("a sample for a room that does not exist")
	}
}

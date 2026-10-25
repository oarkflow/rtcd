package sfu

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// audioPublisher joins with one microphone track and sends packets until the
// returned stop function is called.
func (h *harness) audioPublisher(ctx context.Context, user string) (stop func()) {
	h.t.Helper()
	c := h.newClient(user)
	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "mic", user)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := c.pc.AddTrack(track); err != nil {
		h.t.Fatal(err)
	}
	c.join(ctx)
	done := make(chan struct{})
	go func() {
		var seq uint16
		var ts uint32
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				seq++
				ts += 960
				_ = track.WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 111, SequenceNumber: seq, Timestamp: ts, SSRC: 1}, Payload: []byte{1, 2, 3, 4}})
			}
		}
	}()
	return func() { close(done) }
}

func (h *harness) listener(ctx context.Context, user string) *client {
	c := h.newClient(user)
	if _, err := c.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		h.t.Fatal(err)
	}
	c.join(ctx)
	return c
}

// sending counts the tracks the server is sending a participant.
func (h *harness) sending(user string) int {
	p := h.srv.find(testRoom, user)
	if p == nil {
		return -1
	}
	p.nmu.Lock()
	defer p.nmu.Unlock()
	return len(p.senders)
}

func TestARoomSendsEachViewerOnlyTheLastNSpeakers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := newHarness(t, Config{})
	h.srv.SetPolicy(testRoom, Policy{LastNAudio: 3})
	for i := 0; i < 6; i++ {
		defer h.audioPublisher(ctx, fmt.Sprintf("p%d", i))()
		time.Sleep(30 * time.Millisecond) // a stable join order
	}
	h.listener(ctx, "viewer")

	// With nobody speaking, the first three to arrive are the ones sent.
	waitFor(t, func() bool { return h.sending("viewer") == 3 })
	// A publisher is among the first three, so they are sent the other two.
	waitFor(t, func() bool { return h.sending("p0") == 2 })

	// Lifting the limit sends everyone.
	h.srv.SetPolicy(testRoom, Policy{})
	waitFor(t, func() bool { return h.sending("viewer") == 6 })

	// Narrowing it again takes the surplus away.
	h.srv.SetPolicy(testRoom, Policy{LastNAudio: 2})
	waitFor(t, func() bool { return h.sending("viewer") == 2 })
}

func TestAPinnedPersonIsSentEvenOutsideTheLastN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := newHarness(t, Config{})
	h.srv.SetPolicy(testRoom, Policy{LastNAudio: 1, LastNVideo: 1})
	for i := 0; i < 4; i++ {
		defer h.audioPublisher(ctx, fmt.Sprintf("p%d", i))()
		time.Sleep(30 * time.Millisecond)
	}
	h.listener(ctx, "viewer")
	waitFor(t, func() bool { return h.sending("viewer") == 1 })
	if err := h.srv.Prefer(testRoom, "viewer", Prefs{Pinned: "p3"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return h.sending("viewer") == 2 })
}

func TestARoomPolicyRaisesTheRoomsPeerLimit(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, Config{MaxPeers: 1})
	h.srv.SetPolicy(testRoom, Policy{MaxPeers: 3})
	for i := 0; i < 3; i++ {
		h.listener(ctx, fmt.Sprintf("l%d", i))
	}
	c := h.newClient("l3")
	_, _ = c.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
	offer, _ := c.pc.CreateOffer(nil)
	_ = c.pc.SetLocalDescription(offer)
	if _, err := h.srv.Join(ctx, testRoom, "l3", offer); err != ErrRoomFull {
		t.Fatalf("a fourth person in a room of three: %v", err)
	}
}

// A hundred people in one room: every one of them publishes a microphone and
// every one is sent only the last sixteen speakers. The room must settle (each
// connection negotiated, none starved) and the number of offers the server
// sends must stay near the number of people, not the square of it.
func TestAHundredPeopleShareOneRoom(t *testing.T) {
	if testing.Short() {
		t.Skip("a hundred real peer connections")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const people, lastN = 100, 16
	h := newHarness(t, Config{MaxPeers: people})
	h.quiet = true
	h.srv.SetPolicy(testRoom, Policy{LastNAudio: lastN, LastNVideo: 9})
	start := time.Now()
	for i := 0; i < people; i++ {
		defer h.audioPublisher(ctx, fmt.Sprintf("p%03d", i))()
	}
	joined := time.Since(start)
	deadline := time.Now().Add(90 * time.Second)
	settled := func() bool {
		for i := 0; i < people; i++ {
			want := lastN
			if i < lastN {
				want = lastN - 1 // among the sixteen, and not sent their own
			}
			if h.sending(fmt.Sprintf("p%03d", i)) != want {
				return false
			}
		}
		return true
	}
	for !settled() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !settled() {
		bad := 0
		for i := 0; i < people; i++ {
			if n := h.sending(fmt.Sprintf("p%03d", i)); n != lastN && n != lastN-1 {
				bad++
			}
		}
		t.Fatalf("the room did not settle: %d of %d people are not sent %d tracks", bad, people, lastN)
	}
	h.mu.Lock()
	offers := 0
	for _, n := range h.offersSeen {
		offers += n
	}
	h.mu.Unlock()
	t.Logf("%d people joined in %v and settled in %v; the server sent %d offers (%.1f per person)",
		people, joined.Round(time.Millisecond), time.Since(start).Round(time.Millisecond), offers, float64(offers)/people)
	if offers > people*12 {
		t.Fatalf("%d offers for %d people: negotiation is growing with the square of the room", offers, people)
	}
}

// Without a policy a hundred people all send audio to all: the SDP of every
// connection carries ninety-nine sections. This is not a recommendation, it is
// the measurement that justifies the policy above; it must still work.
func TestAHundredPeopleWithNoPolicyStillSettle(t *testing.T) {
	if testing.Short() {
		t.Skip("a hundred real peer connections")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const people = 100
	h := newHarness(t, Config{MaxPeers: people})
	h.quiet = true
	start := time.Now()
	for i := 0; i < people; i++ {
		defer h.audioPublisher(ctx, fmt.Sprintf("p%03d", i))()
	}
	deadline := time.Now().Add(120 * time.Second)
	settled := func() bool {
		for i := 0; i < people; i++ {
			if h.sending(fmt.Sprintf("p%03d", i)) != people-1 {
				return false
			}
		}
		return true
	}
	for !settled() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	h.mu.Lock()
	offers := 0
	for _, n := range h.offersSeen {
		offers += n
	}
	h.mu.Unlock()
	t.Logf("settled=%v after %v with %d offers (%.1f per person)", settled(), time.Since(start).Round(time.Millisecond), offers, float64(offers)/people)
	if !settled() {
		t.Fatal("not every connection received every other person")
	}
}

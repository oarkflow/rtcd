package sfu

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

const testRoom = "r1"

// harness wires clients to the server: server offers and candidates go to the
// named client, as the hub would deliver them.
type harness struct {
	t       *testing.T
	srv     *Server
	mu      sync.Mutex
	clients map[string]*client
	// dropOffers makes the signaling channel lose a user's next n server offers.
	quiet      bool        // do not log client-side signaling errors
	noReady    bool        // clients do not send Ready after joining
	stopped    atomic.Bool // the test is over: late client goroutines must not log
	speakers   []string    // every speaker change the server announced
	recEvents  []string    // every recording start/stop the server announced
	dropOffers map[string]int
	offersSeen map[string]int
}

func (h *harness) Offer(user, roomID string, offer webrtc.SessionDescription) error {
	h.mu.Lock()
	c := h.clients[user]
	h.offersSeen[user]++
	drop := h.dropOffers[user] > 0
	if drop {
		h.dropOffers[user]--
	}
	h.mu.Unlock()
	if c == nil {
		return ErrNoPeer
	}
	if drop {
		return nil // lost in transit
	}
	go c.onServerOffer(offer)
	return nil
}

func (h *harness) Candidate(user, roomID string, ci webrtc.ICECandidateInit) error {
	h.mu.Lock()
	c := h.clients[user]
	h.mu.Unlock()
	if c != nil {
		_ = c.pc.AddICECandidate(ci)
	}
	return nil
}

type client struct {
	h      *harness
	user   string
	pc     *webrtc.PeerConnection
	mu     sync.Mutex
	joined bool
	queued []webrtc.ICECandidateInit
	tracks chan *webrtc.TrackRemote
}

func (h *harness) newClient(user string) *client { return h.newClientOpts(user, nil) }

// clientOpts tunes a test client's network.
type clientOpts struct {
	// conn, when set, carries all the client's ICE traffic, so a test can cut it.
	conn net.PacketConn
	// fastICE makes the client give up on a silent path in about two seconds.
	fastICE bool
	// onlyVP8 makes the client offer VP8 and Opus and nothing else, like a
	// browser that cannot decode H.264 or VP9.
	onlyVP8 bool
}

func (h *harness) newClientOpts(user string, o *clientOpts) *client {
	h.t.Helper()
	me := &webrtc.MediaEngine{}
	if o != nil && o.onlyVP8 {
		for _, c := range []struct {
			p webrtc.RTPCodecParameters
			k webrtc.RTPCodecType
		}{
			{webrtc.RTPCodecParameters{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, PayloadType: 111}, webrtc.RTPCodecTypeAudio},
			{webrtc.RTPCodecParameters{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}, PayloadType: 96}, webrtc.RTPCodecTypeVideo},
		} {
			if err := me.RegisterCodec(c.p, c.k); err != nil {
				h.t.Fatal(err)
			}
		}
	} else if err := me.RegisterDefaultCodecs(); err != nil {
		h.t.Fatal(err)
	}
	// A browser sends the layer name in an RTP header extension.
	for _, uri := range []string{
		"urn:ietf:params:rtp-hdrext:sdes:mid",
		"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
		"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
	} {
		if err := me.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: uri}, webrtc.RTPCodecTypeVideo); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := me.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: audioLevelURI}, webrtc.RTPCodecTypeAudio); err != nil {
		h.t.Fatal(err)
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	if o != nil && o.fastICE {
		se.SetICETimeouts(400*time.Millisecond, 1500*time.Millisecond, 150*time.Millisecond)
	}
	if o != nil && o.conn != nil {
		se.SetICEUDPMux(ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: o.conn}))
	}
	pc, err := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		h.t.Fatal(err)
	}
	c := &client{h: h, user: user, pc: pc, tracks: make(chan *webrtc.TrackRemote, 16)}
	h.t.Cleanup(func() { _ = pc.Close() })
	h.mu.Lock()
	h.clients[user] = c
	h.mu.Unlock()
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) { c.tracks <- tr })
	pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
		if ci == nil {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.joined {
			c.queued = append(c.queued, ci.ToJSON())
			return
		}
		_ = h.srv.Candidate(testRoom, user, ci.ToJSON())
	})
	return c
}

func (c *client) join(ctx context.Context) {
	c.h.t.Helper()
	// A real browser always offers at least one media section; an offer without
	// any has no ICE credentials to negotiate with.
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
	answer, err := c.h.srv.Join(ctx, testRoom, c.user, *c.pc.LocalDescription())
	if err != nil {
		c.h.t.Fatalf("join %s: %v", c.user, err)
	}
	if err := c.pc.SetRemoteDescription(answer); err != nil {
		c.h.t.Fatal(err)
	}
	if !c.h.noReady {
		_ = c.h.srv.Ready(testRoom, c.user)
	}
	c.mu.Lock()
	c.joined = true
	q := c.queued
	c.queued = nil
	c.mu.Unlock()
	for _, ci := range q {
		_ = c.h.srv.Candidate(testRoom, c.user, ci)
	}
}

func (c *client) onServerOffer(offer webrtc.SessionDescription) {
	fail := func(what string, err error) {
		if !c.h.quiet && !c.h.stopped.Load() {
			c.h.t.Logf("%s: server offer: %s: %v", c.user, what, err)
		}
	}
	if err := c.pc.SetRemoteDescription(offer); err != nil {
		fail("set remote", err)
		return
	}
	answer, err := c.pc.CreateAnswer(nil)
	if err != nil {
		fail("create answer", err)
		return
	}
	if err := c.pc.SetLocalDescription(answer); err != nil {
		fail("set local", err)
		return
	}
	if err := c.h.srv.Answer(testRoom, c.user, *c.pc.LocalDescription()); err != nil {
		fail("answer", err)
	}
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{t: t, clients: map[string]*client{}, dropOffers: map[string]int{}, offersSeen: map[string]int{}}
	cfg.Loopback = true
	srv, err := New(cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	t.Cleanup(func() { _ = srv.Close() })
	t.Cleanup(func() { h.stopped.Store(true) }) // runs first: cleanups are last-in, first-out
	return h
}

func TestForwardsMediaBetweenPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h := newHarness(t, Config{})

	// Ada publishes audio.
	ada := h.newClient("ada")
	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "mic", "ada-stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.pc.AddTrack(track); err != nil {
		t.Fatal(err)
	}
	ada.join(ctx)

	// Bob only listens.
	bob := h.newClient("bob")
	if _, err := bob.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	bob.join(ctx)

	// Ada sends packets until the test ends.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		var seq uint16
		var ts uint32
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				seq++
				ts += 960
				_ = track.WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 111, SequenceNumber: seq, Timestamp: ts, SSRC: 1234}, Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF}})
			}
		}
	}()

	var got *webrtc.TrackRemote
	select {
	case got = <-bob.tracks:
	case <-ctx.Done():
		t.Fatal("bob never received ada's track")
	}
	// The stream id names the publisher, and the server set it: a publisher
	// cannot claim to be someone else.
	if got.StreamID() != "ada" {
		t.Fatalf("stream id %q, want ada", got.StreamID())
	}
	received := 0
	for received < 5 {
		pkt, _, err := got.ReadRTP()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(pkt.Payload) == "\xDE\xAD\xBE\xEF" {
			received++
		}
	}
	// Ada does not get her own audio back.
	select {
	case tr := <-ada.tracks:
		t.Fatalf("ada received a track %s: her own media was echoed", tr.ID())
	case <-time.After(300 * time.Millisecond):
	}
	if st := h.srv.Stats(); st.Rooms != 1 || st.Peers != 2 {
		t.Fatalf("stats %+v", st)
	}

	// Leaving removes the publisher and, when the last one goes, the room.
	h.srv.Leave(testRoom, "ada")
	waitFor(t, func() bool { return len(h.srv.Peers(testRoom)) == 1 })
	h.srv.Leave(testRoom, "bob")
	waitFor(t, func() bool { return h.srv.Stats().Rooms == 0 })
}

func TestRoomLimitsAndBadInput(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, Config{MaxPeers: 1})
	a := h.newClient("a")
	_, _ = a.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
	a.join(ctx)

	b := h.newClient("b")
	_, _ = b.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
	offer, _ := b.pc.CreateOffer(nil)
	_ = b.pc.SetLocalDescription(offer)
	if _, err := h.srv.Join(ctx, testRoom, "b", offer); err != ErrRoomFull {
		t.Fatalf("second peer in a full room: %v", err)
	}
	if _, err := h.srv.Join(ctx, "other", "x", webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: "v=0"}); err == nil {
		t.Fatal("an answer was accepted as a join")
	}
	if _, err := h.srv.Join(ctx, "other", "x", webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: "garbage"}); err == nil {
		t.Fatal("garbage SDP accepted")
	}
	if h.srv.Stats().Rooms != 1 {
		t.Fatalf("a failed join must not leave a room behind: %+v", h.srv.Stats())
	}
	if err := h.srv.Answer(testRoom, "nobody", webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer}); err != ErrNoPeer {
		t.Fatalf("answer for a stranger: %v", err)
	}
	if err := h.srv.Candidate(testRoom, "nobody", webrtc.ICECandidateInit{}); err != ErrNoPeer {
		t.Fatalf("candidate for a stranger: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached within 10s")
}

// Speaker implements SpeakerNotifier.
func (h *harness) Speaker(room, speaker string, participants []string) error {
	h.mu.Lock()
	h.speakers = append(h.speakers, speaker)
	h.mu.Unlock()
	return nil
}

func (h *harness) speakerEvents() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.speakers...)
}

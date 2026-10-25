package sfu

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// ---- a camera that sends three simulcast layers --------------------------------

// layerBytes is the size of one frame per layer: q ~150, h ~500, f ~1200 kbps at 30 fps.
var layerBytes = map[string]int{"q": 600, "h": 2000, "f": 4800}

// layerBase gives each layer its own unrelated numbering, as a real encoder does.
var layerBase = map[string]struct {
	seq uint16
	ts  uint32
	pic uint16
	tl0 uint8
}{
	"q": {1000, 100_000, 100, 10},
	"h": {40000, 9_000_000, 5000, 200},
	"f": {65500, 77_000_000, 30000, 77},
}

type camera struct {
	live    map[string]*atomic.Bool
	needKey map[string]*atomic.Bool
	stop    chan struct{}
	plis    atomic.Int64 // keyframe requests received from the server, all layers
}

func (c *camera) off(rid string) { c.live[rid].Store(false) }
func (c *camera) on(rid string)  { c.live[rid].Store(true); c.needKey[rid].Store(true) }

// startCamera makes the client publish video as the given layers.
func (c *client) startCamera(rids ...string) *camera {
	c.h.t.Helper()
	cam := &camera{live: map[string]*atomic.Bool{}, needKey: map[string]*atomic.Bool{}, stop: make(chan struct{})}
	tracks := map[string]*webrtc.TrackLocalStaticRTP{}
	var sender *webrtc.RTPSender
	for _, rid := range rids {
		tr, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}, "cam", "s-"+c.user, webrtc.WithRTPStreamID(rid))
		if err != nil {
			c.h.t.Fatal(err)
		}
		tracks[rid] = tr
		if sender == nil {
			if sender, err = c.pc.AddTrack(tr); err != nil {
				c.h.t.Fatal(err)
			}
		} else if err := sender.AddEncoding(tr); err != nil {
			c.h.t.Fatal(err)
		}
		cam.live[rid], cam.needKey[rid] = &atomic.Bool{}, &atomic.Bool{}
		cam.live[rid].Store(true)
		cam.needKey[rid].Store(true)
	}
	// Like a browser, tag every packet with the connection's mid and the layer's
	// rid, using the extension ids negotiated in the SDP (Pion leaves this to
	// the application).
	var ext atomic.Pointer[camExt]
	findExt := func() *camExt {
		if e := ext.Load(); e != nil {
			return e
		}
		var e camExt
		for _, he := range sender.GetParameters().HeaderExtensions {
			switch he.URI {
			case "urn:ietf:params:rtp-hdrext:sdes:mid":
				e.midID = uint8(he.ID)
			case "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id":
				e.ridID = uint8(he.ID)
			}
		}
		for _, tr := range c.pc.GetTransceivers() {
			if tr.Sender() == sender {
				e.mid = tr.Mid()
			}
		}
		if e.midID == 0 || e.ridID == 0 || e.mid == "" {
			return nil // not negotiated yet
		}
		ext.Store(&e)
		return &e
	}
	for _, rid := range rids {
		rid := rid
		go func() { // a PLI for this layer asks for a keyframe on it
			for {
				pkts, _, err := sender.ReadSimulcastRTCP(rid)
				if err != nil {
					return
				}
				for _, p := range pkts {
					if _, ok := p.(*rtcp.PictureLossIndication); ok {
						cam.needKey[rid].Store(true)
						cam.plis.Add(1)
					}
				}
			}
		}()
		go cam.run(rid, tracks[rid], findExt)
	}
	c.h.t.Cleanup(func() { close(cam.stop) })
	return cam
}

type camExt struct {
	midID, ridID uint8
	mid          string
}

func (cam *camera) run(rid string, tr *webrtc.TrackLocalStaticRTP, findExt func() *camExt) {
	b := layerBase[rid]
	seq, ts, pic, tl0 := b.seq, b.ts, b.pic, b.tl0
	frame := 0
	tick := time.NewTicker(33 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-cam.stop:
			return
		case <-tick.C:
		}
		e := findExt()
		if e == nil || !cam.live[rid].Load() {
			continue
		}
		key := cam.needKey[rid].Swap(false) || frame%150 == 0
		frame++
		pic = (pic + 1) & 0x7FFF
		tl0++
		ts += 3000
		size := layerBytes[rid]
		for off := 0; off < size; off += 1000 {
			n := min(1000, size-off)
			first := off == 0
			desc := byte(0x80)
			if first {
				desc |= 0x10
			}
			payload := []byte{desc, 0xC0, 0x80 | byte(pic>>8), byte(pic), tl0}
			if first {
				tag := byte(0x01)
				if key {
					tag = 0x00
				}
				payload = append(payload, tag)
			}
			payload = append(payload, fmt.Sprintf("L:%s|", rid)...)
			for len(payload) < n {
				payload = append(payload, 0xAA)
			}
			seq++
			h := rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts, Marker: off+1000 >= size}
			_ = h.SetExtension(e.midID, []byte(e.mid))
			_ = h.SetExtension(e.ridID, []byte(rid))
			_ = tr.WriteRTP(&rtp.Packet{Header: h, Payload: payload})
		}
	}
}

// ---- a receiver that records what arrives ----------------------------------------

type rxPkt struct {
	seq   uint16
	ts    uint32
	pic   uint16
	start bool
	key   bool
	layer string
	at    time.Time
}

type rx struct {
	mu   sync.Mutex
	pkts []rxPkt
	tr   *webrtc.TrackRemote
	pc   *webrtc.PeerConnection
}

func (r *rx) run() {
	for {
		pkt, _, err := r.tr.ReadRTP()
		if err != nil {
			return
		}
		d, ok := parseVP8(pkt.Payload)
		if !ok {
			continue
		}
		p := rxPkt{seq: pkt.SequenceNumber, ts: pkt.Timestamp, pic: d.pic, start: d.start, key: isVP8Keyframe(pkt.Payload), at: time.Now()}
		for i := d.size; i+2 < len(pkt.Payload); i++ {
			if pkt.Payload[i] == 'L' && pkt.Payload[i+1] == ':' {
				p.layer = string(pkt.Payload[i+2])
				break
			}
		}
		r.mu.Lock()
		r.pkts = append(r.pkts, p)
		r.mu.Unlock()
	}
}

func (r *rx) all() []rxPkt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]rxPkt(nil), r.pkts...)
}

func (r *rx) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.pkts) }

func (r *rx) last() rxPkt {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pkts) == 0 {
		return rxPkt{}
	}
	return r.pkts[len(r.pkts)-1]
}

// watch records every video track the client is sent, keyed by the publisher
// (the stream id the server stamped on it).
func (c *client) watch() *watcher {
	w := &watcher{rx: map[string]*rx{}}
	go func() {
		for tr := range c.tracks {
			if tr.Kind() != webrtc.RTPCodecTypeVideo {
				continue
			}
			r := &rx{tr: tr, pc: c.pc}
			w.mu.Lock()
			w.rx[tr.StreamID()] = r
			w.mu.Unlock()
			go r.run()
		}
	}()
	return w
}

type watcher struct {
	mu sync.Mutex
	rx map[string]*rx
}

func (w *watcher) from(publisher string) *rx {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rx[publisher]
}

// eventually polls cond.
func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for: %s", d, what)
}

// layerNow is the layer of the latest packet received from a publisher.
func (w *watcher) layerNow(publisher string) string {
	if r := w.from(publisher); r != nil {
		return r.last().layer
	}
	return ""
}

// continuous checks the properties that make a layer switch invisible to a
// decoder: sequence numbers with no gaps, time that only moves forward, and
// picture ids that count frames.
func continuous(t *testing.T, pkts []rxPkt, what string) {
	t.Helper()
	var lastStart *rxPkt
	for i := 1; i < len(pkts); i++ {
		if pkts[i].seq != pkts[i-1].seq+1 {
			t.Fatalf("%s: sequence jumped from %d to %d at packet %d (layers %s -> %s)", what, pkts[i-1].seq, pkts[i].seq, i, pkts[i-1].layer, pkts[i].layer)
		}
		if int32(pkts[i].ts-pkts[i-1].ts) < 0 {
			t.Fatalf("%s: RTP time went backwards at packet %d: %d -> %d", what, i, pkts[i-1].ts, pkts[i].ts)
		}
		if pkts[i].start {
			if lastStart != nil {
				if got, want := pkts[i].pic, (lastStart.pic+1)&0x7FFF; got != want {
					t.Fatalf("%s: picture id %d after %d at packet %d (layers %s -> %s); decoders need consecutive ids", what, got, lastStart.pic, i, lastStart.layer, pkts[i].layer)
				}
			}
			p := pkts[i]
			lastStart = &p
		}
	}
}

// ---- tests -----------------------------------------------------------------------

func fastAdapt() *adaptCfg {
	return &adaptCfg{UpgradeHold: 400 * time.Millisecond, StepHold: 300 * time.Millisecond, TrialHold: time.Second,
		TrialPeriod: time.Second, MinBackoff: 600 * time.Millisecond, MaxBackoff: 2 * time.Second}
}

// estimates lets a test play the part of each subscriber's network.
type estimates struct{ m sync.Map }

func (e *estimates) set(user string, kbps int) {
	v := &atomic.Int64{}
	v.Store(int64(kbps))
	e.m.Store(user, v)
}
func (e *estimates) fn(_, user string) (int, bool) {
	if v, ok := e.m.Load(user); ok {
		return int(v.(*atomic.Int64).Load()), true
	}
	return 0, false
}

func newSimHarness(t *testing.T, est *estimates, mod func(*Config)) *harness {
	cfg := Config{adapt: fastAdapt(), estimate: est.fn, OfferTimeout: 400 * time.Millisecond, ReconnectGrace: time.Second}
	if mod != nil {
		mod(&cfg)
	}
	return newHarness(t, cfg)
}

func TestSimulcastIsForwardedAsOneContinuousStream(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 400) // a modest link to begin with
	h := newSimHarness(t, est, nil)

	ada := h.newClient("ada")
	cam := ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	if _, err := bob.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	bob.join(ctx)
	w := bob.watch()

	// A new subscriber starts on the smallest layer, so a picture appears at once.
	eventually(t, 10*time.Second, "bob's first picture", func() bool { return w.layerNow("ada") != "" })
	if first := w.from("ada").all()[0]; first.layer != "q" || !first.key {
		t.Fatalf("first packet: layer %q key=%v; want the q keyframe", first.layer, first.key)
	}

	// A good link: quality climbs, one layer at a time.
	est.set("bob", 20000)
	eventually(t, 15*time.Second, "climb to f", func() bool { return w.layerNow("ada") == "f" })
	seen := map[string]bool{}
	for _, p := range w.from("ada").all() {
		seen[p.layer] = true
	}
	if !seen["q"] || !seen["h"] || !seen["f"] {
		t.Fatalf("the climb should pass through every layer: %v", seen)
	}

	// The link collapses (a network switch): back to the smallest layer at once.
	mark := w.from("ada").count()
	est.set("bob", 90)
	eventually(t, 5*time.Second, "drop to q", func() bool { return w.layerNow("ada") == "q" })
	if time.Since(w.from("ada").last().at) > time.Second {
		t.Fatal("the picture froze during the drop")
	}
	_ = mark

	continuous(t, w.from("ada").all(), "q -> h -> f -> q")

	// Quality returns by itself once the link does.
	est.set("bob", 20000)
	eventually(t, 20*time.Second, "recovery to f", func() bool { return w.layerNow("ada") == "f" })
	continuous(t, w.from("ada").all(), "the whole session")
	_ = cam
}

func TestEveryoneSeesEveryoneOnAnyLink(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	users := []string{"ada", "bob", "cy"}
	for _, u := range users {
		est.set(u, 30) // a link far too small for even one stream
	}
	h := newSimHarness(t, est, nil)
	clients := map[string]*client{}
	watchers := map[string]*watcher{}
	for _, u := range users {
		c := h.newClient(u)
		c.startCamera("q", "h", "f")
		c.join(ctx)
		clients[u], watchers[u] = c, c.watch()
	}
	for _, viewer := range users {
		for _, other := range users {
			if viewer == other {
				continue
			}
			v, o := viewer, other
			eventually(t, 15*time.Second, v+" sees "+o, func() bool {
				r := watchers[v].from(o)
				return r != nil && r.count() > 10
			})
			if got := watchers[v].layerNow(o); got != "q" {
				t.Fatalf("%s sees %s on layer %q with almost no bandwidth; everyone must still be visible, on the smallest layer", v, o, got)
			}
		}
	}
	// Nobody receives their own video.
	for _, u := range users {
		if watchers[u].from(u) != nil {
			t.Fatalf("%s is sent their own video", u)
		}
	}
	// With room to spare everyone is at full quality.
	for _, u := range users {
		est.set(u, 30000)
	}
	for _, viewer := range users {
		for _, other := range users {
			if viewer != other {
				v, o := viewer, other
				eventually(t, 25*time.Second, v+" sees "+o+" at full quality", func() bool { return watchers[v].layerNow(o) == "f" })
			}
		}
	}
	for _, viewer := range users {
		for _, other := range users {
			if viewer != other {
				continuous(t, watchers[viewer].from(other).all(), viewer+" watching "+other)
			}
		}
	}
}

func TestTileSizeAndHidingAreHonouredAndShownAgain(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "full quality", func() bool { return w.layerNow("ada") == "f" })

	// A thumbnail: only the small layer is worth the bandwidth.
	if err := h.srv.Prefer(testRoom, "bob", Prefs{Streams: map[string]StreamPref{"ada": {Max: "q"}}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "drop to the thumbnail layer", func() bool { return w.layerNow("ada") == "q" })

	// Hidden: nothing is sent.
	if err := h.srv.Prefer(testRoom, "bob", Prefs{Streams: map[string]StreamPref{"ada": {Paused: true}}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	n := w.from("ada").count()
	time.Sleep(700 * time.Millisecond)
	if grew := w.from("ada").count() - n; grew > 0 {
		t.Fatalf("%d packets arrived for a hidden tile", grew)
	}
	st, _ := h.srv.PeerStats(testRoom, "bob")
	if len(st.Streams) != 1 || !st.Streams[0].Paused || st.UsageKbps != 0 {
		t.Fatalf("stats should show the paused stream and no usage: %+v", st)
	}

	// Shown again: it comes back on a keyframe and the numbering carries on.
	if err := h.srv.Prefer(testRoom, "bob", Prefs{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "video resumes", func() bool { return w.from("ada").count() > n+30 })
	all := w.from("ada").all()
	// Across the pause the packets are consecutive: the decoder is not told about
	// frames it was deliberately not sent.
	for i := 1; i < len(all); i++ {
		if all[i].seq != all[i-1].seq+1 {
			t.Fatalf("sequence jumped %d -> %d at %d", all[i-1].seq, all[i].seq, i)
		}
	}
	if err := h.srv.Prefer(testRoom, "bob", Prefs{MaxKbps: -1}); err != ErrBadPrefs {
		t.Fatalf("negative cap: %v", err)
	}
	if err := h.srv.Prefer(testRoom, "bob", Prefs{Streams: map[string]StreamPref{"ada": {Max: "NOT A LAYER!"}}}); err != ErrBadPrefs {
		t.Fatalf("bad layer name: %v", err)
	}
}

func TestDataSaverCapsBandwidth(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "full quality", func() bool { return w.layerNow("ada") == "f" })
	if err := h.srv.Prefer(testRoom, "bob", Prefs{MaxKbps: 300}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "capped to q", func() bool { return w.layerNow("ada") == "q" })
	st, _ := h.srv.PeerStats(testRoom, "bob")
	if st.UsageKbps > 300 {
		t.Fatalf("a 300 kbps cap, yet %d kbps is being sent", st.UsageKbps)
	}
}

func TestPublisherUplinkDropsTopLayer(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	cam := ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "full quality", func() bool { return w.layerNow("ada") == "f" })

	// Ada's own uplink degrades: her browser stops sending the top layer. Bob,
	// on a great link, must be moved down rather than left looking at a freeze.
	cam.off("f")
	eventually(t, 6*time.Second, "bob moved off the dead layer", func() bool { return w.layerNow("ada") == "h" })
	if time.Since(w.from("ada").last().at) > 500*time.Millisecond {
		t.Fatal("the picture is frozen")
	}
	continuous(t, w.from("ada").all(), "f -> h after the publisher dropped f")

	// When her uplink recovers, bob goes back up by himself.
	cam.on("f")
	eventually(t, 15*time.Second, "bob back on f", func() bool { return w.layerNow("ada") == "f" })
	continuous(t, w.from("ada").all(), "f -> h -> f")
}

func TestSinglePublisherWithoutSimulcastStillWorks(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 100) // tiny: but there is only one layer to send
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("f") // a client that does not do simulcast: one layer
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video from a non-simulcast publisher", func() bool { return w.layerNow("ada") == "f" })
	continuous(t, w.from("ada").all(), "single layer")
}

// ---- network changes and signaling loss ------------------------------------------

// cuttableConn is a UDP socket whose traffic can be cut: a phone leaving Wi-Fi.
type cuttableConn struct {
	net.PacketConn
	down atomic.Bool
}

func newCuttable(t *testing.T) *cuttableConn {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &cuttableConn{PacketConn: c}
}

func (c *cuttableConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.PacketConn.ReadFrom(p)
		if err != nil || !c.down.Load() {
			return n, a, err
		}
		// dropped
	}
}

func (c *cuttableConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if c.down.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, a)
}

func (c *client) iceRestart(t *testing.T) error {
	t.Helper()
	offer, err := c.pc.CreateOffer(&webrtc.OfferOptions{ICERestart: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	answer, err := c.h.srv.Restart(context.Background(), testRoom, c.user, *c.pc.LocalDescription())
	if err != nil {
		return err // a browser would roll back here; Pion cannot, so tests that expect an error stop using this client
	}
	return c.pc.SetRemoteDescription(answer)
}

func TestNetworkSwitchRecoversWithoutRejoining(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)

	net1 := newCuttable(t)
	bob := h.newClientOpts("bob", &clientOpts{conn: net1})
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video before the switch", func() bool { return w.layerNow("ada") == "f" })
	before := w.from("ada").count()

	// The phone leaves Wi-Fi: nothing gets through for a while. The estimate
	// collapses with it, as a real one would.
	net1.down.Store(true)
	est.set("bob", 40)
	time.Sleep(1500 * time.Millisecond)
	stalled := w.from("ada").count()
	time.Sleep(500 * time.Millisecond)
	if w.from("ada").count() > stalled+2 {
		t.Fatal("packets are still arriving through a cut network")
	}
	if got := len(h.srv.Peers(testRoom)); got != 2 {
		t.Fatalf("bob lost his place during a short outage: %d peers", got)
	}

	// The new network is up: restart ICE on the same connection (no rejoin).
	net1.down.Store(false)
	est.set("bob", 8000)
	if err := bob.iceRestart(t); err != nil {
		t.Fatalf("ICE restart: %v", err)
	}
	// His decoder missed frames, so he asks for a keyframe, as a browser would.
	asked := func() {
		if r := w.from("ada"); r != nil {
			_ = bob.pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(r.tr.SSRC())}})
		}
	}
	eventually(t, 15*time.Second, "video resumes on the same connection", func() bool {
		asked()
		return w.from("ada").count() > stalled+60
	})
	if w.from("ada").count() <= before {
		t.Fatal("no new video")
	}
	if got := len(h.srv.Peers(testRoom)); got != 2 {
		t.Fatalf("%d peers after the restart", got)
	}
	// After the outage, quality climbs back up on its own.
	eventually(t, 25*time.Second, "back to full quality", func() bool { return w.layerNow("ada") == "f" })
}

func TestFailedConnectionKeepsItsPlaceForTheGracePeriod(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.ReconnectGrace = 700 * time.Millisecond })
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video", func() bool { return w.layerNow("ada") != "" })

	// ICE gives up on bob. He is not removed straight away...
	h.srv.find(testRoom, "bob").onState(webrtc.PeerConnectionStateFailed)
	time.Sleep(300 * time.Millisecond)
	if len(h.srv.Peers(testRoom)) != 2 {
		t.Fatal("a failed connection was dropped at once; a network switch would end the call")
	}
	// ...and a restart inside the grace period saves his place for good.
	if err := bob.iceRestart(t); err != nil {
		t.Fatal(err)
	}
	time.Sleep(900 * time.Millisecond)
	if len(h.srv.Peers(testRoom)) != 2 {
		t.Fatal("the grace timer removed bob after he had reconnected")
	}

	// Without a restart the place is released when the grace runs out.
	h.srv.find(testRoom, "bob").onState(webrtc.PeerConnectionStateFailed)
	eventually(t, 3*time.Second, "bob removed after the grace period", func() bool { return len(h.srv.Peers(testRoom)) == 1 })
	if err := restartErr(h); err == nil {
		t.Fatal("restart for a removed participant must fail so the client rejoins")
	}
}

func TestLostOfferIsResentAndTheParticipantStillConverges(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)

	bob := h.newClient("bob")
	h.dropOffers["bob"] = 2 // the signaling channel loses the first two offers
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video despite two lost offers", func() bool { return w.layerNow("ada") != "" })
	h.mu.Lock()
	seen := h.offersSeen["bob"]
	h.mu.Unlock()
	if seen < 3 {
		t.Fatalf("the offer was sent %d times; it should have been resent after being lost", seen)
	}
}

func TestOfferLostForGoodKeepsBeingResentUntilAnswered(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.ReconnectGrace = 20 * time.Second })
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)

	bob := h.newClient("bob")
	h.dropOffers["bob"] = 4 // the first offer and three resends are all lost
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 30*time.Second, "video once an offer finally gets through", func() bool { return w.layerNow("ada") != "" })
	h.mu.Lock()
	seen := h.offersSeen["bob"]
	h.mu.Unlock()
	if seen < 5 {
		t.Fatalf("offer sent %d times, want at least 5", seen)
	}
	// An answer to an offer that is no longer outstanding is refused without harm.
	if err := h.srv.Answer(testRoom, "bob", webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: "v=0"}); err != ErrNoOffer {
		t.Fatalf("stale answer: %v", err)
	}
}

func TestParticipantWhoNeverAnswersIsEventuallyReleased(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.ReconnectGrace = 150 * time.Millisecond; c.OfferTimeout = 100 * time.Millisecond })
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	h.dropOffers["bob"] = 1 << 20 // gone for good
	bob.join(ctx)
	eventually(t, 10*time.Second, "an unreachable participant is released", func() bool { return len(h.srv.Peers(testRoom)) == 1 })
}

func TestRestartDuringAServerOfferAsksTheClientToRetry(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.OfferTimeout = 30 * time.Second })
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)

	bob := h.newClient("bob")
	h.dropOffers["bob"] = 1 // the server's offer is out, unanswered
	bob.join(ctx)
	eventually(t, 5*time.Second, "server offer in flight", func() bool {
		p := h.srv.find(testRoom, "bob")
		p.nmu.Lock()
		defer p.nmu.Unlock()
		return p.offer != nil
	})
	// Both sides offering at once ("glare"): the server does not guess; it tells
	// the client to retry once the offer is answered. (A browser client would
	// roll back its own offer and answer the server's.)
	if err := restartErr(h); err != ErrNegotiating {
		t.Fatalf("restart during a server offer: %v", err)
	}
	// The client reconnects its signaling and asks for the offer again.
	if err := h.srv.Resync(testRoom, "bob"); err != nil {
		t.Fatal(err)
	}
	w := bob.watch()
	eventually(t, 10*time.Second, "video after the resync", func() bool { return w.layerNow("ada") != "" })
	if err := bob.iceRestart(t); err != nil {
		t.Fatalf("restart once the server offer is answered: %v", err)
	}
}

func restartErr(h *harness) error {
	_, err := h.srv.Restart(context.Background(), testRoom, "bob", webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: "v=0"})
	return err
}

// ---- scale and churn ---------------------------------------------------------------

func TestFiveWayRoomEveryoneSeesEveryone(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	users := []string{"u1", "u2", "u3", "u4", "u5"}
	for _, u := range users {
		est.set(u, 2500) // each link affords about two layers-worth for four people
	}
	h := newSimHarness(t, est, nil)
	ws := map[string]*watcher{}
	for _, u := range users {
		c := h.newClient(u)
		c.startCamera("q", "h", "f")
		c.join(ctx)
		ws[u] = c.watch()
	}
	for _, v := range users {
		for _, o := range users {
			if v == o {
				continue
			}
			v, o := v, o
			eventually(t, 40*time.Second, v+" sees "+o, func() bool {
				r := ws[v].from(o)
				return r != nil && r.count() > 20 && time.Since(r.last().at) < time.Second
			})
		}
	}
	// The budget is respected: nobody is sent more than their link affords.
	for _, u := range users {
		st, _ := h.srv.PeerStats(testRoom, u)
		if len(st.Streams) != 4 {
			t.Fatalf("%s receives %d videos, want 4", u, len(st.Streams))
		}
		if st.UsageKbps > st.BudgetKbps+300 { // measured rates wobble a little
			t.Fatalf("%s is sent %d kbps against a budget of %d", u, st.UsageKbps, st.BudgetKbps)
		}
	}
}

func TestChurnLeavesNothingBehind(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	users := []string{"stay1", "stay2", "flap"}
	for _, u := range users {
		est.set(u, 20000)
	}
	h := newSimHarness(t, est, nil)
	ws := map[string]*watcher{}
	for _, u := range []string{"stay1", "stay2"} {
		c := h.newClient(u)
		c.startCamera("q", "h", "f")
		c.join(ctx)
		ws[u] = c.watch()
	}
	// One participant joins, leaves, and rejoins again and again (a flaky
	// connection that keeps starting over).
	for i := 0; i < 6; i++ {
		c := h.newClient("flap")
		c.startCamera("q", "h", "f")
		c.join(ctx)
		fw := c.watch()
		for _, v := range []string{"stay1", "stay2"} {
			v := v
			eventually(t, 20*time.Second, fmt.Sprintf("round %d: %s sees flap", i, v), func() bool {
				r := ws[v].from("flap")
				return r != nil && time.Since(r.last().at) < time.Second
			})
		}
		eventually(t, 20*time.Second, fmt.Sprintf("round %d: flap sees stay1", i), func() bool {
			r := fw.from("stay1")
			return r != nil && time.Since(r.last().at) < time.Second
		})
		h.srv.Leave(testRoom, "flap")
		// Their tile goes away for the others rather than freezing.
		eventually(t, 10*time.Second, fmt.Sprintf("round %d: flap removed", i), func() bool {
			for _, v := range []string{"stay1", "stay2"} {
				st, _ := h.srv.PeerStats(testRoom, v)
				for _, s := range st.Streams {
					if s.Publisher == "flap" {
						return false
					}
				}
			}
			return true
		})
		ws["stay1"].mu.Lock()
		delete(ws["stay1"].rx, "flap")
		ws["stay1"].mu.Unlock()
		ws["stay2"].mu.Lock()
		delete(ws["stay2"].rx, "flap")
		ws["stay2"].mu.Unlock()
	}
	// The two who stayed still see each other, untouched by the churn.
	for _, p := range [][2]string{{"stay1", "stay2"}, {"stay2", "stay1"}} {
		r := ws[p[0]].from(p[1])
		if r == nil || time.Since(r.last().at) > time.Second {
			t.Fatalf("%s lost %s during the churn", p[0], p[1])
		}
		continuous(t, r.all(), p[0]+" watching "+p[1]+" through the churn")
	}
	// Everyone leaves: no room, no peer, nothing subscribed.
	h.srv.Leave(testRoom, "stay1")
	h.srv.Leave(testRoom, "stay2")
	eventually(t, 5*time.Second, "empty server", func() bool { return h.srv.Stats() == Stats{} })
}

// ---- the join handshake ------------------------------------------------------------

func TestFirstServerOfferWaitsUntilTheClientIsReady(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.ReadyTimeout = 30 * time.Second })
	h.noReady = true
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	_ = h.srv.Ready(testRoom, "ada")

	bob := h.newClient("bob")
	bob.join(ctx)
	// The server has things to send bob (ada's video), but he has not said he is
	// ready, so nothing may arrive that could overtake his join answer.
	time.Sleep(1200 * time.Millisecond)
	h.mu.Lock()
	early := h.offersSeen["bob"]
	h.mu.Unlock()
	if early != 0 {
		t.Fatalf("%d server offers reached bob before he was ready", early)
	}
	w := bob.watch()
	if err := h.srv.Ready(testRoom, "bob"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, "video after Ready", func() bool { return w.layerNow("ada") != "" })
}

func TestClientThatNeverSaysReadyIsServedAfterTheTimeout(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.ReadyTimeout = 500 * time.Millisecond })
	h.noReady = true
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video without a Ready", func() bool { return w.layerNow("ada") != "" })
}

// Packets from different layers are read by different goroutines; whatever the
// scheduling, what reaches the wire is in sequence.
func TestForwarderWritesStayInOrderAcrossConcurrentLayers(t *testing.T) {
	rec := &orderedRecorder{}
	f := newForwarder(rec, nil, nil)
	f.setTarget("q")
	f.push("q", vp8Packet(1, 1, 1, 1, true, true, "k"))
	f.setTarget("h")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // q keeps flowing while h's keyframe arrives
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			f.push("q", vp8Packet(uint16(2+i), uint32(10+i), uint16(2+i), 1, false, true, "d"))
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond)
		f.push("h", vp8Packet(9000, 1_000_000, 9, 9, true, true, "hk"))
		for i := 1; i < 500; i++ {
			f.push("h", vp8Packet(uint16(9000+i), uint32(1_000_000+i*3000), uint16(9+i), 9, false, true, "hd"))
		}
	}()
	wg.Wait()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i := 1; i < len(rec.seqs); i++ {
		if rec.seqs[i] != rec.seqs[i-1]+1 {
			t.Fatalf("written out of order at %d: %d after %d", i, rec.seqs[i], rec.seqs[i-1])
		}
	}
}

type orderedRecorder struct {
	mu   sync.Mutex
	seqs []uint16
}

func (r *orderedRecorder) WriteRTP(p *rtp.Packet) error {
	r.mu.Lock()
	r.seqs = append(r.seqs, p.SequenceNumber)
	r.mu.Unlock()
	return nil
}

// Heavy churn must not make the connection's description grow without bound.
func TestSectionsAreReusedSoChurnDoesNotInflateTheSDP(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("stay", 20000)
	est.set("flap", 20000)
	h := newSimHarness(t, est, nil)
	stay := h.newClient("stay")
	stay.startCamera("q", "h", "f")
	stay.join(ctx)
	sw := stay.watch()

	for i := 0; i < 25; i++ {
		c := h.newClient("flap")
		c.startCamera("q", "h", "f")
		c.join(ctx)
		eventually(t, 20*time.Second, fmt.Sprintf("round %d: stay sees flap", i), func() bool {
			r := sw.from("flap")
			return r != nil && time.Since(r.last().at) < time.Second
		})
		h.srv.Leave(testRoom, "flap")
		eventually(t, 10*time.Second, fmt.Sprintf("round %d: flap gone", i), func() bool {
			st, _ := h.srv.PeerStats(testRoom, "stay")
			return len(st.Streams) == 0
		})
		sw.mu.Lock()
		delete(sw.rx, "flap")
		sw.mu.Unlock()
	}
	p := h.srv.find(testRoom, "stay")
	if n := len(p.pc.GetTransceivers()); n > 4 {
		t.Fatalf("%d media sections after 25 join/leave cycles; they should have been reused (peak was 1 video)", n)
	}
	if n := len(stay.pc.GetTransceivers()); n > 4 {
		t.Fatalf("the client holds %d media sections", n)
	}
}

// ---- a connection that has really failed ---------------------------------------------

func TestFullyFailedConnectionRecoversWithAnICERestart(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, func(c *Config) {
		c.ICEDisconnectedTimeout, c.ICEFailedTimeout, c.ICEKeepAlive = 400*time.Millisecond, 1500*time.Millisecond, 150*time.Millisecond
		c.ReconnectGrace = 20 * time.Second
	})
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)

	cut := newCuttable(t)
	bob := h.newClientOpts("bob", &clientOpts{conn: cut, fastICE: true})
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video before the outage", func() bool { return w.layerNow("ada") != "" })

	// The network disappears and stays gone until ICE gives up on both ends.
	srvPeer := h.srv.find(testRoom, "bob")
	cut.down.Store(true)
	est.set("bob", 30)
	eventually(t, 15*time.Second, "the server's connection to bob to be FAILED", func() bool {
		return srvPeer.pc.ConnectionState() == webrtc.PeerConnectionStateFailed
	})
	eventually(t, 15*time.Second, "bob's own connection to be FAILED", func() bool {
		return bob.pc.ConnectionState() == webrtc.PeerConnectionStateFailed
	})
	if got := len(h.srv.Peers(testRoom)); got != 2 {
		t.Fatalf("a failed connection cost bob his place: %d peers", got)
	}
	// Everyone else is undisturbed while he is away.
	if st, _ := h.srv.PeerStats(testRoom, "ada"); st.State != "connected" {
		t.Fatalf("ada's connection: %s", st.State)
	}

	// The network returns on a path that works. Restarting ICE from the FAILED
	// state brings the same connection back, with no rejoin.
	cut.down.Store(false)
	est.set("bob", 30000)
	before := w.from("ada").count()
	if err := bob.iceRestart(t); err != nil {
		t.Fatalf("ICE restart from the failed state: %v", err)
	}
	eventually(t, 20*time.Second, "both ends connected again", func() bool {
		return srvPeer.pc.ConnectionState() == webrtc.PeerConnectionStateConnected &&
			bob.pc.ConnectionState() == webrtc.PeerConnectionStateConnected
	})
	asked := func() {
		if r := w.from("ada"); r != nil {
			_ = bob.pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(r.tr.SSRC())}})
		}
	}
	eventually(t, 20*time.Second, "video flows again on the same connection", func() bool {
		asked()
		return w.from("ada").count() > before+60
	})
	if h.srv.find(testRoom, "bob") != srvPeer {
		t.Fatal("bob was replaced by a new connection; the restart should have kept the old one")
	}
	eventually(t, 25*time.Second, "quality returns", func() bool { return w.layerNow("ada") == "f" })
}

// ---- a microphone ------------------------------------------------------------------

// mic is an audio publisher whose loudness the test sets; it tags every Opus
// packet with the RFC 6464 level, as a browser does.
type mic struct {
	level atomic.Uint32 // -dBov: 0 loud, 127 silent
}

func (m *mic) speak()  { m.level.Store(30) }
func (m *mic) silent() { m.level.Store(127) }

func (c *client) startMic() *mic {
	c.h.t.Helper()
	m := &mic{}
	m.silent()
	tr, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "mic", "s-"+c.user)
	if err != nil {
		c.h.t.Fatal(err)
	}
	sender, err := c.pc.AddTrack(tr)
	if err != nil {
		c.h.t.Fatal(err)
	}
	go func() { // keep the sender's feedback read
		for {
			if _, _, err := sender.ReadRTCP(); err != nil {
				return
			}
		}
	}()
	stop := make(chan struct{})
	c.h.t.Cleanup(func() { close(stop) })
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
			}
			var id uint8
			for _, he := range sender.GetParameters().HeaderExtensions {
				if he.URI == audioLevelURI {
					id = uint8(he.ID)
				}
			}
			if id == 0 {
				continue // not negotiated yet
			}
			seq++
			ts += 960
			lvl := uint8(m.level.Load())
			voice := byte(0)
			if lvl < 100 {
				voice = 0x80
			}
			h := rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts}
			_ = h.SetExtension(id, []byte{voice | lvl})
			_ = tr.WriteRTP(&rtp.Packet{Header: h, Payload: []byte{0xFC, 0xFF, 0xFE}})
		}
	}()
	return m
}

func TestActiveSpeakerIsDetectedAnnouncedAndFavoured(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("ada", 30000)
	est.set("bob", 30000)
	est.set("cy", 860) // budget ~650 kbps: the floor for two people (300) plus ONE step up
	h := newSimHarness(t, est, nil)
	mics := map[string]*mic{}
	watchers := map[string]*watcher{}
	for _, u := range []string{"ada", "bob", "cy"} {
		c := h.newClient(u)
		c.startCamera("q", "h", "f")
		mics[u] = c.startMic()
		c.join(ctx)
		watchers[u] = c.watch()
	}
	for _, v := range []string{"ada", "bob", "cy"} {
		for _, o := range []string{"ada", "bob", "cy"} {
			if v != o {
				v, o := v, o
				eventually(t, 30*time.Second, v+" sees "+o, func() bool { return watchers[v].layerNow(o) != "" })
			}
		}
	}
	if got := h.srv.Speaker(testRoom); got != "" {
		t.Fatalf("speaker %q in a silent room", got)
	}

	mics["ada"].speak()
	eventually(t, 5*time.Second, "ada becomes the speaker", func() bool { return h.srv.Speaker(testRoom) == "ada" })
	// cy's link affords one step up; it goes to the person talking, and
	// the other is still shown, on the smallest layer.
	eventually(t, 15*time.Second, "cy sees the speaker better than the other", func() bool {
		return rankOf(watchers["cy"].layerNow("ada")) > rankOf(watchers["cy"].layerNow("bob")) && watchers["cy"].layerNow("bob") == "q"
	})

	mics["ada"].silent()
	mics["bob"].speak()
	eventually(t, 8*time.Second, "bob takes over", func() bool { return h.srv.Speaker(testRoom) == "bob" })
	eventually(t, 15*time.Second, "cy's spare quality follows the speaker", func() bool {
		return rankOf(watchers["cy"].layerNow("bob")) > rankOf(watchers["cy"].layerNow("ada")) && watchers["cy"].layerNow("ada") == "q"
	})
	for _, o := range []string{"ada", "bob"} {
		if r := watchers["cy"].from(o); r == nil || time.Since(r.last().at) > time.Second {
			t.Fatalf("cy lost sight of %s while the highlight moved", o)
		}
	}
	st, _ := h.srv.PeerStats(testRoom, "cy")
	if st.Speaker != "bob" {
		t.Fatalf("stats name %q as the speaker", st.Speaker)
	}

	// Everyone goes quiet: the highlight clears after a pause, not instantly.
	mics["bob"].silent()
	eventually(t, 8*time.Second, "no speaker once everyone is quiet", func() bool { return h.srv.Speaker(testRoom) == "" })
	ev := h.speakerEvents()
	if len(ev) > 6 {
		t.Fatalf("%d speaker announcements for ada -> bob -> nobody: %v", len(ev), ev)
	}
}

// ---- recording -----------------------------------------------------------------------

// RecordingNotifier on the harness.
func (h *harness) Recording(room string, on bool, by string, participants []string) error {
	h.mu.Lock()
	h.recEvents = append(h.recEvents, fmt.Sprintf("%v:%s:%d", on, by, len(participants)))
	h.mu.Unlock()
	return nil
}

func TestRecordingProducesPlayableFilesForEveryone(t *testing.T) {
	needFFmpeg(t)
	ctx := context.Background()
	est := &estimates{}
	for _, u := range []string{"ada", "bob", "cy"} {
		est.set(u, 30000)
	}
	dir := t.TempDir()
	h := newSimHarness(t, est, func(c *Config) { c.RecordDir = dir })
	ws := map[string]*watcher{}
	join := func(u string) {
		c := h.newClient(u)
		c.startRealCamera("q", "h", "f")
		c.startRealMic()
		c.join(ctx)
		ws[u] = c.watch()
	}
	join("ada")
	join("bob")
	for _, p := range [][2]string{{"ada", "bob"}, {"bob", "ada"}} {
		p := p
		eventually(t, 20*time.Second, p[0]+" sees "+p[1], func() bool { r := ws[p[0]].from(p[1]); return r != nil && r.count() > 30 })
	}

	if _, err := h.srv.StopRecording(testRoom, "ada"); err != ErrNotRecording {
		t.Fatalf("stop without a recording: %v", err)
	}
	info, err := h.srv.StartRecording(testRoom, "ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.StartRecording(testRoom, "bob"); err != ErrRecording {
		t.Fatalf("second recording of one room: %v", err)
	}
	if st, _ := h.srv.PeerStats(testRoom, "bob"); !st.Recording {
		t.Fatal("stats do not tell bob the call is being recorded")
	}
	time.Sleep(2500 * time.Millisecond)
	join("cy") // joins mid-recording: recorded from then on
	eventually(t, 20*time.Second, "cy sees ada", func() bool { r := ws["cy"].from("ada"); return r != nil && r.count() > 30 })
	if st, _ := h.srv.PeerStats(testRoom, "cy"); !st.Recording {
		t.Fatal("a late joiner is not told about the recording")
	}
	time.Sleep(4 * time.Second)

	final, err := h.srv.StopRecording(testRoom, "ada")
	if err != nil {
		t.Fatal(err)
	}
	if final.ID != info.ID || final.StoppedAt == nil || final.StartedBy != "ada" {
		t.Fatalf("recording info %+v", final)
	}
	byUser := map[string][]RecordingFile{}
	for _, f := range final.Files {
		byUser[f.User] = append(byUser[f.User], f)
	}
	for _, u := range []string{"ada", "bob", "cy"} {
		if len(byUser[u]) == 0 {
			t.Fatalf("no recording of %s: %+v", u, final.Files)
		}
	}
	for u, files := range byUser {
		f := files[len(files)-1]
		p := ffprobe(t, f.Path)
		var vcodec, acodec string
		var frames int
		for _, s := range p.Streams {
			switch s.CodecType {
			case "video":
				vcodec = s.CodecName
				if s.Width != 320 || s.Height != 240 {
					t.Errorf("%s: picture size %dx%d, want 320x240", u, s.Width, s.Height)
				}
				fmt.Sscan(s.Frames, &frames)
			case "audio":
				acodec = s.CodecName
			}
		}
		if vcodec != "vp8" || acodec != "opus" {
			t.Errorf("%s: codecs %q/%q, want vp8/opus (%+v)", u, vcodec, acodec, p.Streams)
		}
		if frames < 25 {
			t.Errorf("%s: only %d video frames", u, frames)
		}
		decodes(t, f.Path) // not just a valid container: every frame decodes
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(final.Files[0].Path), "manifest.json")); err != nil {
		t.Fatalf("no manifest: %v", err)
	}
	// Everyone was told when it started and stopped.
	h.mu.Lock()
	ev := append([]string(nil), h.recEvents...)
	h.mu.Unlock()
	// Start (to the two people there), a notice to the one who joined later (cy),
	// and stop (to all three).
	if len(ev) != 3 || ev[0] != "true:ada:2" || ev[1] != "true:ada:1" || ev[2] != "false:ada:3" {
		t.Fatalf("recording notifications: %v", ev)
	}
	if st, _ := h.srv.PeerStats(testRoom, "bob"); st.Recording {
		t.Fatal("stats still say recording after it stopped")
	}
}

func TestRecordingIsOffUnlessConfiguredAndNamesAreSafe(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("ada", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	if _, err := h.srv.StartRecording(testRoom, "ada"); err != ErrRecordingDisabled {
		t.Fatalf("recording without a directory: %v", err)
	}
	if safeName("../../etc/passwd") == "../../etc/passwd" || strings.ContainsAny(safeName("a/b\\c:d"), `/\:`) || safeName("..") == ".." {
		t.Fatal("a participant or room name can escape the recording directory")
	}
}

// ---- other codecs --------------------------------------------------------------------

const h264Fmtp = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"

// startH264Camera publishes H.264 simulcast: keyframes are SPS+PPS (a STAP-A)
// followed by an IDR slice; delta frames are single non-IDR slices.
func (c *client) startH264Camera(rids ...string) *camera {
	c.h.t.Helper()
	cam := &camera{live: map[string]*atomic.Bool{}, needKey: map[string]*atomic.Bool{}, stop: make(chan struct{})}
	tracks := map[string]*webrtc.TrackLocalStaticRTP{}
	var sender *webrtc.RTPSender
	for _, rid := range rids {
		tr, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: h264Fmtp},
			"cam", "s-"+c.user, webrtc.WithRTPStreamID(rid))
		if err != nil {
			c.h.t.Fatal(err)
		}
		tracks[rid] = tr
		if sender == nil {
			if sender, err = c.pc.AddTrack(tr); err != nil {
				c.h.t.Fatal(err)
			}
		} else if err := sender.AddEncoding(tr); err != nil {
			c.h.t.Fatal(err)
		}
		cam.live[rid], cam.needKey[rid] = &atomic.Bool{}, &atomic.Bool{}
		cam.live[rid].Store(true)
		cam.needKey[rid].Store(true)
	}
	var ext atomic.Pointer[camExt]
	findExt := func() *camExt {
		if e := ext.Load(); e != nil {
			return e
		}
		var e camExt
		for _, he := range sender.GetParameters().HeaderExtensions {
			switch he.URI {
			case "urn:ietf:params:rtp-hdrext:sdes:mid":
				e.midID = uint8(he.ID)
			case "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id":
				e.ridID = uint8(he.ID)
			}
		}
		for _, tr := range c.pc.GetTransceivers() {
			if tr.Sender() == sender {
				e.mid = tr.Mid()
			}
		}
		if e.midID == 0 || e.ridID == 0 || e.mid == "" {
			return nil
		}
		ext.Store(&e)
		return &e
	}
	for _, rid := range rids {
		rid := rid
		go func() {
			for {
				pkts, _, err := sender.ReadSimulcastRTCP(rid)
				if err != nil {
					return
				}
				for _, p := range pkts {
					if _, ok := p.(*rtcp.PictureLossIndication); ok {
						cam.needKey[rid].Store(true)
					}
				}
			}
		}()
		go func() {
			b := layerBase[rid]
			seq, ts, frame := b.seq, b.ts, 0
			tick := time.NewTicker(33 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-cam.stop:
					return
				case <-tick.C:
				}
				e := findExt()
				if e == nil || !cam.live[rid].Load() {
					continue
				}
				key := cam.needKey[rid].Swap(false) || frame%150 == 0
				frame++
				ts += 3000
				tag := []byte(fmt.Sprintf("L:%s|", rid))
				var packets [][]byte
				if key {
					sps := append([]byte{0x67, 0x42, 0xe0, 0x1f}, tag...)
					pps := []byte{0x68, 0xce, 0x3c, 0x80}
					stap := []byte{24, byte(len(sps) >> 8), byte(len(sps))}
					stap = append(stap, sps...)
					stap = append(stap, 0, byte(len(pps)))
					stap = append(stap, pps...)
					idr := append([]byte{0x65, 0x88}, tag...)
					idr = append(idr, make([]byte, layerBytes[rid]/4)...)
					packets = [][]byte{stap, idr}
				} else {
					d := append([]byte{0x41, 0x9a}, tag...)
					d = append(d, make([]byte, layerBytes[rid]/4)...)
					packets = [][]byte{d}
				}
				for i, pl := range packets {
					seq++
					h := rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts, Marker: i == len(packets)-1}
					_ = h.SetExtension(e.midID, []byte(e.mid))
					_ = h.SetExtension(e.ridID, []byte(rid))
					_ = tracks[rid].WriteRTP(&rtp.Packet{Header: h, Payload: pl})
				}
			}
		}()
	}
	c.h.t.Cleanup(func() { close(cam.stop) })
	return cam
}

// h264Layer reads which layer a forwarded H.264 packet came from, and whether it
// opens a keyframe, from the tag the camera put in it.
func h264Tag(payload []byte) (layer string, parameterSets bool) {
	for i := 0; i+3 < len(payload); i++ {
		if payload[i] == 'L' && payload[i+1] == ':' && payload[i+3] == '|' {
			return string(payload[i+2]), isH264Keyframe(payload)
		}
	}
	return "", false
}

func TestH264SimulcastSwitchesLayersAtParameterSets(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 400)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startH264Camera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)

	// Read raw packets: this codec has no picture ids to check, so the properties
	// are the numbering and that every switch begins at SPS/PPS.
	type seen struct {
		seq   uint16
		ts    uint32
		layer string
		sps   bool
	}
	var mu sync.Mutex
	var got []seen
	go func() {
		for tr := range bob.tracks {
			if tr.StreamID() != "ada" {
				continue
			}
			for {
				pkt, _, err := tr.ReadRTP()
				if err != nil {
					return
				}
				l, sps := h264Tag(pkt.Payload)
				mu.Lock()
				got = append(got, seen{pkt.SequenceNumber, pkt.Timestamp, l, sps})
				mu.Unlock()
			}
		}
	}()
	last := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(got) == 0 {
			return ""
		}
		return got[len(got)-1].layer
	}
	eventually(t, 15*time.Second, "H.264 video arrives", func() bool { return last() != "" })
	est.set("bob", 30000)
	eventually(t, 20*time.Second, "climb to f", func() bool { return last() == "f" })
	est.set("bob", 90)
	eventually(t, 8*time.Second, "drop to q", func() bool { return last() == "q" })

	mu.Lock()
	defer mu.Unlock()
	switches := 0
	for i := 1; i < len(got); i++ {
		if got[i].seq != got[i-1].seq+1 {
			t.Fatalf("sequence jumped %d -> %d at %d", got[i-1].seq, got[i].seq, i)
		}
		if int32(got[i].ts-got[i-1].ts) < 0 {
			t.Fatalf("time went backwards at %d", i)
		}
		if got[i].layer != got[i-1].layer {
			switches++
			if !got[i].sps {
				t.Fatalf("switched %s -> %s at packet %d, which is not the start of a keyframe (no SPS/PPS)", got[i-1].layer, got[i].layer, i)
			}
		}
	}
	if switches < 3 {
		t.Fatalf("only %d layer switches", switches)
	}
	if got[0].layer != "q" || !got[0].sps {
		t.Fatalf("first packet: layer %s sps=%v", got[0].layer, got[0].sps)
	}
}

// ---- VP9 SVC -------------------------------------------------------------------------

// startSVCCamera publishes one VP9 stream carrying three spatial layers per
// picture, as a browser does with scalabilityMode L3T3_KEY.
func (c *client) startSVCCamera() *camera {
	c.h.t.Helper()
	cam := &camera{live: map[string]*atomic.Bool{"f": {}}, needKey: map[string]*atomic.Bool{"q": {}}, stop: make(chan struct{})}
	cam.live["f"].Store(true)
	cam.needKey["q"].Store(true)
	tr, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP9, ClockRate: 90000, SDPFmtpLine: "profile-id=0"}, "cam", "s-"+c.user)
	if err != nil {
		c.h.t.Fatal(err)
	}
	sender, err := c.pc.AddTrack(tr)
	if err != nil {
		c.h.t.Fatal(err)
	}
	go func() {
		for {
			pkts, _, err := sender.ReadRTCP()
			if err != nil {
				return
			}
			for _, p := range pkts {
				if _, ok := p.(*rtcp.PictureLossIndication); ok {
					cam.needKey["q"].Store(true)
				}
			}
		}
	}()
	go func() {
		seq, ts, pic := uint16(3000), uint32(1_000_000), uint16(0)
		frame := 0
		tick := time.NewTicker(33 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-cam.stop:
				return
			case <-tick.C:
			}
			key := cam.needKey["q"].Swap(false) || frame%120 == 0
			frame++
			pic = (pic + 1) & 0x7FFF
			ts += 3000
			for sid := 0; sid < 3; sid++ {
				if !cam.live["f"].Load() && sid == 2 {
					continue // the publisher's uplink dropped the top layer
				}
				last := sid == 2 || (!cam.live["f"].Load() && sid == 1)
				b0 := byte(0x80 | 0x20 | 0x08 | 0x04) // I L B E: one packet per layer's frame
				if !(key && sid == 0) {
					b0 |= 0x40 // P: predicted
				}
				layer := byte(sid<<1) | 0x01*b2u(sid > 0)
				payload := []byte{b0, 0x80 | byte(pic>>8), byte(pic), layer, 0x01}
				payload = append(payload, []byte(fmt.Sprintf("S:%d|", sid))...)
				payload = append(payload, make([]byte, 200*(sid+1))...)
				seq++
				_ = tr.WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts, Marker: last}, Payload: payload})
			}
		}
	}()
	c.h.t.Cleanup(func() { close(cam.stop) })
	return cam
}

func TestVP9SVCDeliversOnlyTheLayersEachViewerCanUse(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("small", 150) // a budget of ~125 kbps: the ~50 kbps base layer, but not the next step
	est.set("big", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	cam := ada.startSVCCamera()
	ada.join(ctx)

	type pk struct {
		seq    uint16
		sid    int
		marker bool
		pic    uint16
	}
	collect := func(user string) (*sync.Mutex, *[]pk) {
		c := h.newClient(user)
		c.join(ctx)
		var mu sync.Mutex
		var got []pk
		go func() {
			for tr := range c.tracks {
				if tr.StreamID() != "ada" {
					continue
				}
				for {
					p, _, err := tr.ReadRTP()
					if err != nil {
						return
					}
					d, ok := parseVP9(p.Payload)
					if !ok {
						continue
					}
					mu.Lock()
					got = append(got, pk{p.SequenceNumber, int(d.sid), p.Marker, d.pic})
					mu.Unlock()
				}
			}
		}()
		return &mu, &got
	}
	smallMu, small := collect("small")
	bigMu, big := collect("big")

	topSID := func(mu *sync.Mutex, got *[]pk) int {
		mu.Lock()
		defer mu.Unlock()
		if len(*got) == 0 {
			return -1
		}
		m := 0
		for _, p := range (*got)[max(0, len(*got)-30):] {
			m = max(m, p.sid)
		}
		return m
	}
	eventually(t, 25*time.Second, "the big viewer receives all three spatial layers", func() bool { return topSID(bigMu, big) == 2 })
	eventually(t, 25*time.Second, "the small viewer receives only the base layer", func() bool { return topSID(smallMu, small) == 0 && len(*small) > 40 })

	check := func(name string, mu *sync.Mutex, got *[]pk) {
		mu.Lock()
		defer mu.Unlock()
		for i := 1; i < len(*got); i++ {
			a, b := (*got)[i-1], (*got)[i]
			if b.seq != a.seq+1 {
				t.Fatalf("%s: sequence %d -> %d at %d; dropped layers must leave no gap", name, a.seq, b.seq, i)
			}
		}
	}
	check("small", smallMu, small)
	check("big", bigMu, big)
	// The small viewer's only layer ends every picture, so it must carry the marker.
	smallMu.Lock()
	for _, p := range (*small)[len(*small)-20:] {
		if !p.marker {
			smallMu.Unlock()
			t.Fatal("the small viewer's last (only) layer of a picture has no marker; its decoder would never know the picture ended")
		}
	}
	smallMu.Unlock()

	// The viewer's link improves, then the publisher's uplink loses the top layer.
	est.set("small", 30000)
	eventually(t, 25*time.Second, "the small viewer climbs to all layers", func() bool { return topSID(smallMu, small) == 2 })
	cam.live["f"].Store(false)
	eventually(t, 10*time.Second, "viewers follow the publisher down to two layers", func() bool { return topSID(bigMu, big) == 1 && topSID(smallMu, small) == 1 })
	check("small after the climb and the drop", smallMu, small)
	check("big after the drop", bigMu, big)
}

// ---- different codecs in one room -----------------------------------------------------

// rawWatch counts forwarded packets per publisher without assuming a codec.
type rawWatcher struct {
	mu     sync.Mutex
	counts map[string]int
	codec  map[string]string
}

func (c *client) rawWatch() *rawWatcher {
	w := &rawWatcher{counts: map[string]int{}, codec: map[string]string{}}
	go func() {
		for tr := range c.tracks {
			if tr.Kind() != webrtc.RTPCodecTypeVideo {
				continue
			}
			who := tr.StreamID()
			w.mu.Lock()
			w.codec[who] = tr.Codec().MimeType
			w.mu.Unlock()
			go func() {
				for {
					if _, _, err := tr.ReadRTP(); err != nil {
						return
					}
					w.mu.Lock()
					w.counts[who]++
					w.mu.Unlock()
				}
			}()
		}
	}()
	return w
}

func (w *rawWatcher) n(who string) int       { w.mu.Lock(); defer w.mu.Unlock(); return w.counts[who] }
func (w *rawWatcher) mime(who string) string { w.mu.Lock(); defer w.mu.Unlock(); return w.codec[who] }

func TestEveryoneSeesEveryoneWhateverCodecTheySend(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	for _, u := range []string{"ada", "bob", "cy"} {
		est.set(u, 30000)
	}
	h := newSimHarness(t, est, nil)
	ada, bob, cy := h.newClient("ada"), h.newClient("bob"), h.newClient("cy")
	ada.startH264Camera("q", "h", "f") // H.264 simulcast
	bob.startCamera("q", "h", "f")     // VP8 simulcast
	cy.startSVCCamera()                // VP9 SVC
	for _, c := range []*client{ada, bob, cy} {
		c.join(ctx)
	}
	w := map[string]*rawWatcher{"ada": ada.rawWatch(), "bob": bob.rawWatch(), "cy": cy.rawWatch()}
	want := map[string]string{"ada": "video/H264", "bob": "video/VP8", "cy": "video/VP9"}
	for _, viewer := range []string{"ada", "bob", "cy"} {
		for pub, mime := range want {
			if viewer == pub {
				continue
			}
			viewer, pub, mime := viewer, pub, mime
			eventually(t, 30*time.Second, viewer+" receives "+pub+"'s "+mime, func() bool { return w[viewer].n(pub) > 30 })
			if got := w[viewer].mime(pub); !strings.EqualFold(got, mime) {
				t.Fatalf("%s receives %s's video as %s, want %s", viewer, pub, got, mime)
			}
		}
	}
}

func TestAViewerWhoCannotDecodeACodecIsToldAndStillSeesTheRest(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	for _, u := range []string{"ada", "bob", "old"} {
		est.set(u, 30000)
	}
	h := newSimHarness(t, est, nil)
	ada, bob := h.newClient("ada"), h.newClient("bob")
	ada.startH264Camera("q", "h", "f") // H.264
	bob.startCamera("q", "h", "f")     // VP8
	ada.join(ctx)
	bob.join(ctx)

	old := h.newClientOpts("old", &clientOpts{onlyVP8: true}) // a browser with no H.264
	old.join(ctx)
	w := old.rawWatch()
	eventually(t, 30*time.Second, "old sees bob (VP8)", func() bool { return w.n("bob") > 30 })
	// ada's H.264 cannot be delivered to a connection that never offered it. The
	// server says so, instead of attaching a sender that would silently carry nothing.
	eventually(t, 10*time.Second, "the stats explain why ada's video is missing", func() bool {
		st, _ := h.srv.PeerStats(testRoom, "old")
		return len(st.Unavailable) == 1 && st.Unavailable[0].Publisher == "ada" && strings.Contains(st.Unavailable[0].Reason, "H264")
	})
	if w.n("ada") != 0 {
		t.Fatal("packets of an undeliverable codec reached the viewer")
	}
	// Everyone else still sees everyone they can.
	wa := ada.rawWatch()
	eventually(t, 30*time.Second, "ada sees bob", func() bool { return wa.n("bob") > 30 })
	eventually(t, 30*time.Second, "ada sees old's absence of video gracefully", func() bool { st, _ := h.srv.PeerStats(testRoom, "ada"); return st.State == "connected" })
}

// ---- recovery after an ICE restart, without anyone asking ------------------------------

// A browser's decoder asks for a keyframe after a path change, but slowly and
// not always on time. The server must not depend on it.

func TestASubscribersICERestartMakesTheServerAskForKeyframesByItself(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	cam := ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video before the restart", func() bool { return w.layerNow("ada") != "" && w.from("ada") != nil && w.from("ada").count() > 30 })
	time.Sleep(time.Second) // the settling keyframes are done
	before := cam.plis.Load()
	if err := bob.iceRestart(t); err != nil {
		t.Fatal(err)
	}
	// Bob sends no PLI at all. The server asks for him.
	eventually(t, 3*time.Second, "the server asking the publisher for a keyframe", func() bool { return cam.plis.Load() > before })
	// ... and, the camera having answered, it stops asking.
	time.Sleep(2 * time.Second)
	settled := cam.plis.Load()
	time.Sleep(2 * time.Second)
	if cam.plis.Load() != settled {
		t.Fatalf("keyframe requests went on after the keyframe arrived (%d -> %d)", settled, cam.plis.Load())
	}
	if settled-before > 8 {
		t.Fatalf("%d keyframe requests for one restart", settled-before)
	}
}

func TestAPublishersICERestartMakesTheServerAskForKeyframesByItself(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	cam := ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video before the restart", func() bool { return w.from("ada") != nil && w.from("ada").count() > 30 })
	time.Sleep(time.Second)
	before := cam.plis.Load()
	if err := ada.iceRestart(t); err != nil { // the publisher's path changed
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "the server asking the publisher for a keyframe", func() bool { return cam.plis.Load() > before })
	// Video keeps flowing to the viewer throughout.
	n := w.from("ada").count()
	eventually(t, 10*time.Second, "video still arriving", func() bool { return w.from("ada").count() > n+30 })
}

func TestARoomThatNobodyRestartsIsNeverAskedForExtraKeyframes(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	cam := ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video", func() bool { return w.from("ada") != nil && w.from("ada").count() > 30 })
	time.Sleep(3 * time.Second) // let the start-up keyframes finish
	before := cam.plis.Load()
	time.Sleep(5 * time.Second)
	if got := cam.plis.Load() - before; got != 0 {
		t.Fatalf("a healthy stream was asked for %d keyframes in 5 seconds", got)
	}
}

// TestARealPathChangeRecoversQuicklyAndWithoutAnyoneAskingForAKeyframe is the case
// an ICE restart exists for: the publisher's network is gone, then a new one is
// up. From the restart to the viewer seeing the publisher's video again must be
// short, and nobody but the server asks for the keyframe.
func TestARealPathChangeRecoversQuicklyAndWithoutAnyoneAskingForAKeyframe(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	est.set("ada", 30000)
	h := newSimHarness(t, est, nil)
	net1 := newCuttable(t)
	ada := h.newClientOpts("ada", &clientOpts{conn: net1})
	cam := ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video before the change", func() bool { return w.from("ada") != nil && w.from("ada").count() > 60 })

	net1.down.Store(true) // the publisher leaves its network
	time.Sleep(1200 * time.Millisecond)
	atCut := w.from("ada").count()
	time.Sleep(300 * time.Millisecond)
	if w.from("ada").count() > atCut+2 {
		t.Fatal("packets still arrive through a cut network")
	}

	net1.down.Store(false) // the new network is up
	plisBefore := cam.plis.Load()
	t0 := time.Now()
	if err := ada.iceRestart(t); err != nil {
		t.Fatal(err)
	}
	base := w.from("ada").count()
	var took time.Duration
	eventually(t, 10*time.Second, "the viewer seeing the publisher again", func() bool {
		if w.from("ada").count() > base+30 {
			took = time.Since(t0)
			return true
		}
		return false
	})
	t.Logf("from the ICE restart to the viewer receiving the publisher's video again: %v", took.Round(time.Millisecond))
	if took > 3*time.Second {
		t.Fatalf("recovery took %v", took)
	}
	time.Sleep(1500 * time.Millisecond)
	t.Logf("keyframe requests the publisher received: before the restart %d, after %d", plisBefore, cam.plis.Load())
	if cam.plis.Load() <= plisBefore {
		t.Fatal("the server never asked the publisher for a keyframe, and the viewer asked for none")
	}
}

// A browser that restarts ICE keeps sending on its old path until it has moved to
// a pair of the new generation, which takes seconds. The server must keep that old
// path working meanwhile: anything it drops is lost video, and the loss makes the
// browser cut its bandwidth estimate. This test restarts the server's ICE agent
// with new credentials and never lets the client move, so the client carries on
// exactly as a browser does during the switch.
func TestMediaOnTheOldPathIsStillReceivedWhileARestartIsInProgress(t *testing.T) {
	ctx := context.Background()
	est := &estimates{}
	est.set("bob", 30000)
	est.set("ada", 30000)
	h := newSimHarness(t, est, nil)
	ada := h.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	bob := h.newClient("bob")
	bob.join(ctx)
	w := bob.watch()
	eventually(t, 15*time.Second, "video before the restart", func() bool { return w.from("ada") != nil && w.from("ada").count() > 60 })
	time.Sleep(time.Second)

	offer, err := ada.pc.CreateOffer(nil) // the client's own offer, unchanged ...
	if err != nil {
		t.Fatal(err)
	}
	restart := offer
	restart.SDP = regexp.MustCompile(`(?m)^a=ice-ufrag:.*$`).ReplaceAllString(restart.SDP, "a=ice-ufrag:restartedufrag1")
	restart.SDP = regexp.MustCompile(`(?m)^a=ice-pwd:.*$`).ReplaceAllString(restart.SDP, "a=ice-pwd:restartedpassword0123456789")
	if _, err := h.srv.Restart(ctx, testRoom, "ada", restart); err != nil { // ... with new credentials, and its answer never applied
		t.Fatal(err)
	}

	base := w.from("ada").count()
	time.Sleep(1500 * time.Millisecond)
	got := w.from("ada").count() - base
	t.Logf("packets of the publisher's video that reached the viewer in the 1.5 s after the server restarted ICE (publisher still on its old path): %d", got)
	if got < 40 {
		t.Fatalf("only %d packets arrived: the server dropped the old path the moment it restarted", got)
	}
	if n := len(h.srv.Peers(testRoom)); n != 2 {
		t.Fatalf("%d people in the room", n)
	}
}

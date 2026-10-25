package sfu

import (
	"testing"
	"time"

	"github.com/pion/rtp"
)

// vp8Packet builds a VP8 RTP packet: descriptor with a 15-bit picture id and a
// TL0PICIDX, then a payload header whose P bit says key or delta frame.
func vp8Packet(seq uint16, ts uint32, pic uint16, tl0 uint8, key, start bool, marker string) *rtp.Packet {
	desc := byte(0x80) // X
	if start {
		desc |= 0x10
	}
	frameTag := byte(0x01) // P=1: delta
	if key {
		frameTag = 0x00
	}
	payload := []byte{desc, 0xC0, 0x80 | byte(pic>>8), byte(pic), tl0, frameTag}
	payload = append(payload, marker...)
	h := rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts, SSRC: 1}
	_ = h.SetExtension(3, []byte{1}) // a publisher-session extension that must not reach subscribers
	return &rtp.Packet{Header: h, Payload: payload}
}

type recorder struct{ pkts []*rtp.Packet }

func (r *recorder) WriteRTP(p *rtp.Packet) error { r.pkts = append(r.pkts, p); return nil }

type clk struct{ t time.Time }

func (c *clk) now() time.Time { return c.t }

func newTestForwarder() (*forwarder, *recorder, *clk, *[]string) {
	rec, c, asked := &recorder{}, &clk{t: time.Unix(1_000, 0)}, &[]string{}
	f := newForwarder(rec, func(rid string) { *asked = append(*asked, rid) }, c.now)
	return f, rec, c, asked
}

func TestVP8Parsing(t *testing.T) {
	p := vp8Packet(1, 1, 0x1234, 7, true, true, "x").Payload
	d, ok := parseVP8(p)
	if !ok || !d.start || !d.pic15 || d.pic != 0x1234 || !d.hasTL0 || d.tl0 != 7 || d.size != 5 {
		t.Fatalf("%+v ok=%v", d, ok)
	}
	if !isVP8Keyframe(p) {
		t.Fatal("keyframe not detected")
	}
	if isVP8Keyframe(vp8Packet(1, 1, 1, 1, false, true, "x").Payload) {
		t.Fatal("a delta frame was taken for a keyframe")
	}
	// The continuation of a keyframe is not a keyframe start: switching there
	// would hand the decoder half a frame.
	if isVP8Keyframe(vp8Packet(2, 1, 1, 1, true, false, "x").Payload) {
		t.Fatal("a continuation packet counted as a keyframe start")
	}
	// 7-bit picture id, no extension, truncated input.
	short := []byte{0x90, 0x80, 0x05, 0x00}
	if d, ok := parseVP8(short); !ok || d.pic15 || d.pic != 5 {
		t.Fatalf("7-bit: %+v %v", d, ok)
	}
	for _, bad := range [][]byte{nil, {0x80}, {0x80, 0x80}, {0x80, 0x80, 0x80}, {0x80, 0x40}} {
		if _, ok := parseVP8(bad); ok {
			t.Fatalf("accepted truncated descriptor %v", bad)
		}
	}
}

func TestFirstKeyframeStartsTheStream(t *testing.T) {
	f, rec, _, asked := newTestForwarder()
	f.setTarget("h")
	if len(*asked) != 1 || (*asked)[0] != "h" {
		t.Fatalf("a keyframe should be requested on the wanted layer: %v", *asked)
	}
	f.push("h", vp8Packet(10, 1000, 5, 1, false, true, "delta")) // not decodable yet
	f.push("q", vp8Packet(10, 1000, 5, 1, true, true, "other"))  // wrong layer
	if len(rec.pkts) != 0 {
		t.Fatalf("forwarded %d packets before a keyframe on the wanted layer", len(rec.pkts))
	}
	f.push("h", vp8Packet(11, 1003, 6, 1, true, true, "key"))
	f.push("h", vp8Packet(12, 1006, 7, 1, false, true, "next"))
	if len(rec.pkts) != 2 || rec.pkts[0].SequenceNumber != 11 || rec.pkts[1].SequenceNumber != 12 {
		t.Fatalf("got %d packets", len(rec.pkts))
	}
	if rec.pkts[0].Extension || len(rec.pkts[0].Extensions) != 0 {
		t.Fatal("the publisher's header extensions were forwarded")
	}
}

func TestLayerSwitchKeepsNumberingContinuous(t *testing.T) {
	f, rec, c, _ := newTestForwarder()
	f.setTarget("q")
	// Layer q: seq 100.., ts 5000.., picture ids 40.., tl0 9..
	f.push("q", vp8Packet(100, 5000, 40, 9, true, true, "q-key"))
	f.push("q", vp8Packet(101, 8000, 41, 10, false, true, "q-delta"))
	c.t = c.t.Add(33 * time.Millisecond)

	f.setTarget("f")
	// q keeps flowing while f is not yet decodable: no gap in the picture.
	f.push("q", vp8Packet(102, 11000, 42, 11, false, true, "q-delta2"))
	f.push("f", vp8Packet(9000, 700000, 3, 200, false, true, "f-delta")) // not a keyframe: ignored
	if n := len(rec.pkts); n != 3 {
		t.Fatalf("expected q to continue, got %d packets", n)
	}
	c.t = c.t.Add(33 * time.Millisecond)
	// f's keyframe: completely unrelated numbering.
	f.push("f", vp8Packet(9001, 700100, 3, 200, true, true, "f-key"))
	c.t = c.t.Add(33 * time.Millisecond)
	f.push("f", vp8Packet(9002, 703100, 4, 200, false, true, "f-delta2"))
	f.push("q", vp8Packet(103, 14000, 43, 12, false, true, "q-late")) // q is no longer forwarded
	if len(rec.pkts) != 5 {
		t.Fatalf("got %d packets", len(rec.pkts))
	}

	prev := rec.pkts[2] // last q packet
	pd, _ := parseVP8(prev.Payload)
	for i, p := range rec.pkts[3:] {
		d, _ := parseVP8(p.Payload)
		if p.SequenceNumber != prev.SequenceNumber+1 {
			t.Errorf("packet %d: seq %d after %d (a gap makes the receiver NACK forever)", i, p.SequenceNumber, prev.SequenceNumber)
		}
		if p.Timestamp <= prev.Timestamp {
			t.Errorf("packet %d: timestamp %d did not advance from %d", i, p.Timestamp, prev.Timestamp)
		}
		if i == 0 && (d.pic != pd.pic+1 || d.tl0 != pd.tl0+1) {
			t.Errorf("picture id %d / tl0 %d after %d / %d", d.pic, d.tl0, pd.pic, pd.tl0)
		}
		if i == 1 && d.pic != pd.pic+1 {
			t.Errorf("picture id must keep counting frames: %d", d.pic)
		}
		prev, pd = p, d
	}
	// The wall-clock gap (33 ms = ~2970 ticks) is what separates the first f
	// frame from the last q frame in RTP time, whatever f's own timestamps say.
	gap := rec.pkts[3].Timestamp - rec.pkts[2].Timestamp
	if gap < 2900 || gap > 3100 {
		t.Errorf("timestamp gap %d, want ~2970 (33ms at 90kHz)", gap)
	}
	if got := f.state(); got.Cur != "f" || got.Switches != 2 {
		t.Fatalf("state %+v", got)
	}
}

func TestSequenceAndPictureWrap(t *testing.T) {
	f, rec, _, _ := newTestForwarder()
	f.setTarget("q")
	f.push("q", vp8Packet(65534, 100, 0x7FFE, 255, true, true, "k"))
	f.push("q", vp8Packet(65535, 200, 0x7FFF, 255, false, true, "d"))
	f.setTarget("f")
	f.push("f", vp8Packet(5, 300, 10, 3, true, true, "k2"))
	last := rec.pkts[len(rec.pkts)-1]
	d, _ := parseVP8(last.Payload)
	if last.SequenceNumber != 0 {
		t.Errorf("seq after 65535 should wrap to 0, got %d", last.SequenceNumber)
	}
	if d.pic != 0 || d.tl0 != 0 {
		t.Errorf("picture id after 0x7FFF should wrap to 0, got pic=%d tl0=%d", d.pic, d.tl0)
	}
}

func TestPauseResumeWaitsForAKeyframe(t *testing.T) {
	f, rec, c, asked := newTestForwarder()
	f.setTarget("h")
	f.push("h", vp8Packet(1, 10, 1, 1, true, true, "k"))
	f.setPaused(true)
	f.push("h", vp8Packet(2, 13, 2, 1, false, true, "d")) // dropped while paused
	if len(rec.pkts) != 1 {
		t.Fatalf("forwarded while paused: %d", len(rec.pkts))
	}
	c.t = c.t.Add(time.Second)
	*asked = nil
	f.setPaused(false)
	if len(*asked) != 1 {
		t.Fatalf("resume must request a keyframe: %v", *asked)
	}
	f.push("h", vp8Packet(30, 90, 20, 2, false, true, "d")) // the decoder missed frames: wait
	if len(rec.pkts) != 1 {
		t.Fatal("resumed on a delta frame")
	}
	f.push("h", vp8Packet(31, 93, 21, 2, true, true, "k"))
	if len(rec.pkts) != 2 || rec.pkts[1].SequenceNumber != 2 {
		t.Fatalf("numbering must continue across the pause: %+v", rec.pkts[len(rec.pkts)-1].Header)
	}
}

func TestKeyframeRequestsAreThrottled(t *testing.T) {
	f, _, c, asked := newTestForwarder()
	f.setTarget("f")
	for i := 0; i < 50; i++ { // a burst of deltas while waiting
		f.push("f", vp8Packet(uint16(i), uint32(i), 1, 1, false, true, "d"))
	}
	if len(*asked) != 1 {
		t.Fatalf("%d keyframe requests in a burst", len(*asked))
	}
	c.t = c.t.Add(keyframeAskInterval + time.Millisecond)
	f.push("f", vp8Packet(60, 60, 1, 1, false, true, "d"))
	if len(*asked) != 2 {
		t.Fatalf("a still-missing keyframe should be asked for again: %d", len(*asked))
	}
	// The subscriber's own PLI is honoured, on the layer it is receiving.
	f.push("f", vp8Packet(61, 61, 1, 1, true, true, "k"))
	c.t = c.t.Add(time.Second)
	f.keyframeWanted()
	if got := (*asked)[len(*asked)-1]; got != "f" || len(*asked) != 3 {
		t.Fatalf("PLI handling: %v", *asked)
	}
}

func TestForwarderNeverMutatesTheSharedPacket(t *testing.T) {
	f, _, _, _ := newTestForwarder()
	f.setTarget("q")
	f.push("q", vp8Packet(1, 1, 1, 1, true, true, "a"))
	f.setTarget("f")
	pkt := vp8Packet(500, 900, 77, 5, true, true, "b")
	before := append([]byte(nil), pkt.Payload...)
	seq, ts := pkt.SequenceNumber, pkt.Timestamp
	f.push("f", pkt)
	if string(pkt.Payload) != string(before) || pkt.SequenceNumber != seq || pkt.Timestamp != ts || !pkt.Extension {
		t.Fatal("the packet shared by all subscribers was modified")
	}
}

type discard struct{}

func (discard) WriteRTP(*rtp.Packet) error { return nil }

// BenchmarkForwarderPush is the cost, per subscriber, of forwarding one packet
// of a layer already being forwarded (the common case), with picture-id
// rewriting after a layer switch.
func BenchmarkForwarderPush(b *testing.B) {
	f := newForwarder(discard{}, nil, nil)
	f.setTarget("q")
	f.push("q", vp8Packet(1, 1, 1, 1, true, true, "k"))
	f.setTarget("f")
	f.push("f", vp8Packet(9000, 9000, 50, 50, true, true, "k")) // a switch: offsets are now non-zero
	pkt := vp8Packet(9001, 9003, 51, 50, false, true, "delta")
	pkt.Payload = append(pkt.Payload, make([]byte, 1000)...)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt.Payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt.SequenceNumber = uint16(9001 + i)
		f.push("f", pkt)
	}
}

// ---- recovery after damage ------------------------------------------------------------

// playing starts a stream on layer h: a keyframe, then n delta frames in order.
func playing(t *testing.T, f *forwarder, c *clk, n int) (seq uint16) {
	t.Helper()
	f.setTarget("h")
	f.push("h", vp8Packet(100, 1000, 1, 1, true, true, "key"))
	seq = 101
	for i := 0; i < n; i++ {
		c.t = c.t.Add(30 * time.Millisecond)
		f.push("h", vp8Packet(seq, 1000+uint32(i+1)*3000, uint16(2+i), 1, false, true, "d"))
		seq++
	}
	return seq
}

func asksFor(asked *[]string, rid string) int {
	n := 0
	for _, a := range *asked {
		if a == rid {
			n++
		}
	}
	return n
}

func TestABurstOfMissingPacketsMakesTheForwarderAskForAKeyframeUntilOneComes(t *testing.T) {
	f, rec, c, asked := newTestForwarder()
	next := playing(t, f, c, 10)
	before := asksFor(asked, "h")
	// 20 packets vanish upstream (a path change); the stream resumes with delta frames.
	next += 20
	for i := 0; i < 6; i++ {
		c.t = c.t.Add(350 * time.Millisecond) // slower than the ask interval
		f.push("h", vp8Packet(next, 200000+uint32(i)*3000, uint16(50+i), 1, false, true, "d"))
		next++
	}
	if got := asksFor(asked, "h") - before; got < 4 {
		t.Fatalf("a damaged picture was asked for a keyframe only %d times in 2 seconds", got)
	}
	// Meanwhile what arrives is still forwarded: the subscriber is no worse off.
	if len(rec.pkts) < 16 {
		t.Fatalf("%d packets forwarded", len(rec.pkts))
	}
	// The keyframe arrives: asking stops.
	c.t = c.t.Add(350 * time.Millisecond)
	f.push("h", vp8Packet(next, 300000, 60, 1, true, true, "key"))
	next++
	at := asksFor(asked, "h")
	for i := 0; i < 5; i++ {
		c.t = c.t.Add(350 * time.Millisecond)
		f.push("h", vp8Packet(next, 310000+uint32(i)*3000, uint16(61+i), 1, false, true, "d"))
		next++
	}
	if asksFor(asked, "h") != at {
		t.Fatal("the forwarder kept asking after the keyframe arrived")
	}
}

func TestSmallGapsAreLeftToRetransmissionAndLateOrDuplicatePacketsAreNotGaps(t *testing.T) {
	f, _, c, asked := newTestForwarder()
	next := playing(t, f, c, 10)
	before := asksFor(asked, "h")
	next += 3 // three lost: NACK repairs that
	for i := 0; i < 5; i++ {
		c.t = c.t.Add(350 * time.Millisecond)
		f.push("h", vp8Packet(next, 200000+uint32(i)*3000, uint16(50+i), 1, false, true, "d"))
		next++
	}
	// Reordering and duplicates.
	f.push("h", vp8Packet(next-3, 1, 1, 1, false, true, "late"))
	f.push("h", vp8Packet(next-1, 1, 1, 1, false, true, "dup"))
	c.t = c.t.Add(350 * time.Millisecond)
	f.push("h", vp8Packet(next, 400000, 70, 1, false, true, "d"))
	if got := asksFor(asked, "h") - before; got != 0 {
		t.Fatalf("a small gap or reordering caused %d keyframe requests", got)
	}
	// The sequence number wrapping around is not a gap either.
	f2, _, c2, asked2 := newTestForwarder()
	f2.setTarget("h")
	f2.push("h", vp8Packet(65530, 1000, 1, 1, true, true, "key"))
	b2 := asksFor(asked2, "h")
	for i := 0; i < 12; i++ {
		c2.t = c2.t.Add(350 * time.Millisecond)
		f2.push("h", vp8Packet(uint16(65531+i), 1000+uint32(i+1)*3000, uint16(2+i), 1, false, true, "d"))
	}
	if asksFor(asked2, "h") != b2 {
		t.Fatal("a sequence number wrapping around was taken for a gap")
	}
}

func TestExpectKeyframeAsksAtOnceAndKeepsAskingForAWhile(t *testing.T) {
	f, _, c, asked := newTestForwarder()
	next := playing(t, f, c, 5)
	b := asksFor(asked, "h")
	c.t = c.t.Add(time.Second)
	f.expectKeyframe() // the path under the subscriber or publisher changed
	if asksFor(asked, "h") != b+1 {
		t.Fatalf("no immediate request: %v", *asked)
	}
	for i := 0; i < 8; i++ {
		c.t = c.t.Add(350 * time.Millisecond)
		f.push("h", vp8Packet(next, 500000+uint32(i)*3000, uint16(90+i), 1, false, true, "d"))
		next++
	}
	if got := asksFor(asked, "h") - b; got < 7 {
		t.Fatalf("asked %d times", got)
	}
	// It does not go on for ever: after the window it leaves it to the subscriber.
	c.t = c.t.Add(keyframeRecoveryWindow + time.Second)
	f.push("h", vp8Packet(next, 900000, 120, 1, false, true, "d"))
	next++
	at := asksFor(asked, "h")
	for i := 0; i < 5; i++ {
		c.t = c.t.Add(350 * time.Millisecond)
		f.push("h", vp8Packet(next, 910000+uint32(i)*3000, uint16(121+i), 1, false, true, "d"))
		next++
	}
	if asksFor(asked, "h") != at {
		t.Fatal("the forwarder asked for ever")
	}
}

func TestAPausedOrIdleForwarderDoesNotAskOnExpect(t *testing.T) {
	f, _, _, asked := newTestForwarder()
	f.expectKeyframe() // nothing wanted yet
	if len(*asked) != 0 {
		t.Fatalf("asked with no target: %v", *asked)
	}
	f.setTarget("h")
	f.setPaused(true)
	n := len(*asked)
	f.expectKeyframe()
	if len(*asked) != n {
		t.Fatal("asked for a video nobody is being sent")
	}
}

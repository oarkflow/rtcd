package sfu

import (
	"testing"
	"time"

	"github.com/pion/rtp"
)

// svcPacket builds a VP9 packet of one picture's spatial layer: layer indices
// present, non-flexible mode, 15-bit picture id.
func svcPacket(seq uint16, pic uint16, sid int, start, end, inter bool, marker bool) *rtp.Packet {
	b0 := byte(0x80 | 0x20) // I, L
	if inter {
		b0 |= 0x40
	}
	if start {
		b0 |= 0x08
	}
	if end {
		b0 |= 0x04
	}
	layer := byte(sid<<1) | 0x01*b2u(sid > 0) // D: depends on the layer below
	p := []byte{b0, 0x80 | byte(pic>>8), byte(pic), layer, 0x05, 0xAA, 0xBB}
	return &rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: uint32(pic) * 3000, Marker: marker}, Payload: p}
}

func b2u(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// picture pushes one picture of three spatial layers, each in one packet
// (so every packet both starts and ends its layer's frame), and returns the
// next input sequence number.
func picture(f *svcForwarder, seq uint16, pic uint16, key bool) uint16 {
	for sid := 0; sid < 3; sid++ {
		inter := !(key && sid == 0)
		f.push(sidNames[sid], svcPacket(seq, pic, sid, sid == 0, true, inter, sid == 2))
		seq++
	}
	return seq
}

func newSVCTest() (*svcForwarder, *recorder, *clk, *[]string) {
	rec, c, asked := &recorder{}, &clk{t: time.Unix(5_000, 0)}, &[]string{}
	return newSVCForwarder(rec, func(rid string) { *asked = append(*asked, rid) }, c.now), rec, c, asked
}

func TestSVCForwardsOnlyTheLayersUpToTheTarget(t *testing.T) {
	f, rec, _, _ := newSVCTest()
	f.setTarget("h")
	seq := picture(f, 100, 1, true)
	seq = picture(f, seq, 2, false)
	seq = picture(f, seq, 3, false)
	if n := len(rec.pkts); n != 6 {
		t.Fatalf("3 pictures x 2 layers = 6 packets, got %d", n)
	}
	for i, p := range rec.pkts {
		d, _ := parseVP9(p.Payload)
		if d.sid > 1 {
			t.Fatalf("packet %d is spatial layer %d, above the target h", i, d.sid)
		}
		if i > 0 && p.SequenceNumber != rec.pkts[i-1].SequenceNumber+1 {
			t.Fatalf("packet %d: seq %d after %d; dropping a layer must leave no gap", i, p.SequenceNumber, rec.pkts[i-1].SequenceNumber)
		}
		// The encoder marked only the top layer; the subscriber's top layer is h.
		if d.sid == 1 && !p.Marker {
			t.Fatalf("packet %d is the last of its picture for this subscriber but has no marker", i)
		}
		if d.sid == 0 && p.Marker {
			t.Fatalf("packet %d has a marker mid-picture", i)
		}
	}
	_ = seq
}

func TestSVCFullQualityIsPassedThroughUntouched(t *testing.T) {
	f, rec, _, _ := newSVCTest()
	f.setTarget("f")
	picture(f, 7, 1, true)
	picture(f, 10, 2, false)
	if len(rec.pkts) != 6 {
		t.Fatalf("%d packets", len(rec.pkts))
	}
	for i, p := range rec.pkts {
		if p.SequenceNumber != uint16(7+i)+uint16(0) && i < 3 {
			t.Fatalf("seq %d", p.SequenceNumber)
		}
		if p.Marker != (i%3 == 2) {
			t.Fatalf("packet %d marker=%v", i, p.Marker)
		}
	}
}

func TestSVCNeedsAKeyframeToStartAndToGoUp(t *testing.T) {
	f, rec, c, asked := newSVCTest()
	f.setTarget("q")
	seq := picture(f, 1, 1, false) // a delta picture first: undecodable
	if len(rec.pkts) != 0 {
		t.Fatal("forwarded before any keyframe")
	}
	if len(*asked) == 0 {
		t.Fatal("no keyframe requested while waiting")
	}
	seq = picture(f, seq, 2, true)
	seq = picture(f, seq, 3, false)
	if len(rec.pkts) != 2 {
		t.Fatalf("expected the base layer of two pictures, got %d", len(rec.pkts))
	}

	// Asking for more: no change until a keyframe; the keyframe is requested.
	c.t = c.t.Add(time.Second)
	*asked = nil
	f.setTarget("f")
	if len(*asked) != 1 {
		t.Fatalf("going up must ask for a keyframe: %v", *asked)
	}
	seq = picture(f, seq, 4, false)
	seq = picture(f, seq, 5, false)
	before := len(rec.pkts)
	if layers := maxSID(rec.pkts); layers != 0 {
		t.Fatalf("went up to layer %d without a keyframe", layers)
	}
	seq = picture(f, seq, 6, true) // the keyframe: now all three layers
	seq = picture(f, seq, 7, false)
	if got := len(rec.pkts) - before; got != 6 {
		t.Fatalf("after the keyframe: %d packets for two pictures, want 6", got)
	}
	if maxSID(rec.pkts[before:]) != 2 {
		t.Fatal("did not reach the top layer")
	}
	// Numbering stayed contiguous through the whole climb.
	for i := 1; i < len(rec.pkts); i++ {
		if rec.pkts[i].SequenceNumber != rec.pkts[i-1].SequenceNumber+1 {
			t.Fatalf("gap at %d: %d after %d", i, rec.pkts[i].SequenceNumber, rec.pkts[i-1].SequenceNumber)
		}
	}
	_ = seq
}

func maxSID(pkts []*rtp.Packet) int {
	m := 0
	for _, p := range pkts {
		if d, ok := parseVP9(p.Payload); ok && int(d.sid) > m {
			m = int(d.sid)
		}
	}
	return m
}

func TestSVCGoingDownIsImmediateAtAPictureBoundary(t *testing.T) {
	f, rec, _, _ := newSVCTest()
	f.setTarget("f")
	seq := picture(f, 1, 1, true)
	seq = picture(f, seq, 2, false)
	f.setTarget("q")
	// Mid-picture the layer must not change: send only layer 0 and 1 of the next
	// picture first. The change applies at the *start* of a picture.
	seq = picture(f, seq, 3, false)
	seq = picture(f, seq, 4, false)
	if len(rec.pkts) != 8 {
		t.Fatalf("2 full pictures (6 packets) + 2 base-layer pictures (2 packets) = 8, got %d", len(rec.pkts))
	}
	last := rec.pkts[len(rec.pkts)-2:]
	for _, p := range last {
		if d, _ := parseVP9(p.Payload); d.sid != 0 {
			t.Fatalf("still forwarding layer %d after the target dropped to q", d.sid)
		}
		if !p.Marker {
			t.Fatal("the only layer forwarded must end each picture")
		}
	}
	for i := 1; i < len(rec.pkts); i++ {
		if rec.pkts[i].SequenceNumber != rec.pkts[i-1].SequenceNumber+1 {
			t.Fatalf("gap at %d", i)
		}
	}
	_ = seq
}

func TestSVCPauseResumeAndLatePackets(t *testing.T) {
	f, rec, c, asked := newSVCTest()
	f.setTarget("h")
	seq := picture(f, 50, 1, true)
	f.setPaused(true)
	seq = picture(f, seq, 2, false)
	if len(rec.pkts) != 2 {
		t.Fatalf("forwarded while paused: %d", len(rec.pkts))
	}
	c.t = c.t.Add(time.Second)
	*asked = nil
	f.setPaused(false)
	if len(*asked) != 1 {
		t.Fatal("resume must request a keyframe")
	}
	seq = picture(f, seq, 3, false) // undecodable for a viewer that missed pictures
	if len(rec.pkts) != 2 {
		t.Fatal("resumed on a delta picture")
	}
	seq = picture(f, seq, 4, true)
	if len(rec.pkts) != 4 {
		t.Fatalf("got %d", len(rec.pkts))
	}
	if rec.pkts[2].SequenceNumber != rec.pkts[1].SequenceNumber+1 {
		t.Fatalf("numbering must carry on across the pause: %d after %d", rec.pkts[2].SequenceNumber, rec.pkts[1].SequenceNumber)
	}
	// A packet that arrives after later ones cannot be renumbered into place.
	n := len(rec.pkts)
	f.push("q", svcPacket(seq-30, 1, 0, true, true, false, false))
	if len(rec.pkts) != n {
		t.Fatal("a late packet was forwarded")
	}
	_ = seq
}

func TestSVCRejectsGarbageAndUnknownLayers(t *testing.T) {
	f, rec, _, _ := newSVCTest()
	f.setTarget("f")
	f.push("q", &rtp.Packet{Payload: nil})
	f.push("zz", svcPacket(1, 1, 0, true, true, false, true))
	if len(rec.pkts) != 0 {
		t.Fatal("forwarded garbage")
	}
}

func TestSVCDoesNotModifyTheSharedPacket(t *testing.T) {
	f, _, _, _ := newSVCTest()
	f.setTarget("h")
	pkt := svcPacket(900, 5, 1, true, true, false, false)
	_ = pkt.Header.SetExtension(3, []byte{1})
	before := append([]byte(nil), pkt.Payload...)
	f.push("q", svcPacket(899, 5, 0, true, true, false, false))
	f.push("h", pkt)
	if pkt.Marker || pkt.SequenceNumber != 900 || !pkt.Extension || string(pkt.Payload) != string(before) {
		t.Fatal("the packet shared by all subscribers was modified")
	}
}

func TestSVCForwarderRecoversFromABurstGapAndAfterExpectKeyframe(t *testing.T) {
	f, _, c, asked := newSVCTest()
	f.setTarget("f")
	seq, pic := uint16(100), uint16(1)
	step := func(key bool) {
		c.t = c.t.Add(350 * time.Millisecond) // slower than the ask interval
		seq = picture(f, seq, pic, key)
		pic++
	}
	step(true)
	for i := 0; i < 4; i++ {
		step(false)
	}
	base := len(*asked)
	seq += 25 // a path change eats 25 packets
	for i := 0; i < 5; i++ {
		step(false)
	}
	if got := len(*asked) - base; got < 4 {
		t.Fatalf("a damaged SVC stream was asked for a keyframe %d times", got)
	}
	step(true) // the keyframe arrives
	at := len(*asked)
	for i := 0; i < 4; i++ {
		step(false)
	}
	if len(*asked) != at {
		t.Fatal("kept asking after the keyframe")
	}
	// A small gap is left to retransmission.
	seq += 2
	for i := 0; i < 4; i++ {
		step(false)
	}
	if len(*asked) != at {
		t.Fatal("a small gap caused keyframe requests")
	}
	c.t = c.t.Add(time.Second)
	f.expectKeyframe()
	if len(*asked) != at+1 {
		t.Fatal("expectKeyframe did not ask at once")
	}
}

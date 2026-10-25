package sfu

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtp"
)

// rtpWriter is where a forwarder sends packets: a webrtc.TrackLocalStaticRTP in
// production, a recorder in tests.
type rtpWriter interface {
	WriteRTP(*rtp.Packet) error
}

// forwarder is one subscriber's view of one published video track.
//
// The publisher sends several layers (q, h, f) of the same picture, each with
// its own SSRC, sequence numbers, timestamps and VP8 picture ids. The
// subscriber must see a single stream, so the forwarder
//
//   - forwards only the layer it is on, and moves to another one only at a
//     keyframe of that layer (anything else would show a corrupt picture);
//   - renumbers sequence numbers, RTP timestamps, picture ids and TL0PICIDX at
//     the moment of a move, so the stream continues where the old layer left
//     off;
//   - waits, asking the publisher for a keyframe, while the layer it wants is
//     not yet decodable.
type forwarder struct {
	out         rtpWriter
	askKeyframe func(rid string)
	now         func() time.Time
	codec       codecKind

	// wmu orders writes to the same order as the numbering. Each layer is read by
	// its own goroutine; without it the last packet of the old layer and the
	// first of the new one could be written in either order.
	wmu sync.Mutex

	mu      sync.Mutex
	cur     string // layer being forwarded; "" before the first keyframe
	target  string // layer wanted; "" means forward nothing
	paused  bool
	started bool

	seqOff  uint16
	tsOff   uint32
	picOff  uint16
	tl0Off  uint8
	lastSeq uint16
	lastTS  uint32
	lastPic uint16
	lastTL0 uint8

	lastWrite time.Time
	lastAsk   time.Time
	switches  int

	// Recovery. After the path under the publisher or the subscriber changed, or
	// a burst of the publisher's packets went missing, the subscriber's picture
	// is broken until the next keyframe, and it may be a long time before its own
	// decoder asks for one. needKey makes the forwarder ask, and keep asking
	// whenever the publisher's packets arrive, until a keyframe passes.
	needKey   bool
	needUntil time.Time
	lastIn    uint16 // the newest sequence number of the current layer seen
	seenIn    bool

	sentBytes atomic.Uint64
}

// keyframeAskInterval is the shortest gap between keyframe requests from one
// forwarder, so a layer that is slow to produce one is not flooded.
const keyframeAskInterval = 300 * time.Millisecond

// keyframeRecoveryWindow is how long a forwarder keeps asking for a keyframe
// after damage before it gives up and leaves it to the subscriber's own requests.
const keyframeRecoveryWindow = 15 * time.Second

// gapBurst is the number of consecutive packets of one layer that must go missing
// for the forwarder to treat the picture as damaged. A few lost packets are
// repaired by retransmission; a burst this size, such as a path change causes, is
// not worth waiting for.
const gapBurst = 5

func newForwarder(out rtpWriter, ask func(rid string), now func() time.Time) *forwarder {
	return newCodecForwarder(codecVP8, out, ask, now)
}

func newCodecForwarder(codec codecKind, out rtpWriter, ask func(rid string), now func() time.Time) *forwarder {
	if now == nil {
		now = time.Now
	}
	return &forwarder{out: out, askKeyframe: ask, now: now, codec: codec}
}

// layerState is a forwarder's current position.
type layerState struct {
	Cur, Target string
	Paused      bool
	Switches    int
}

func (f *forwarder) state() layerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return layerState{f.cur, f.target, f.paused, f.switches}
}

// setTarget chooses the layer to forward; "" stops forwarding. The move happens
// at that layer's next keyframe, which is requested now.
func (f *forwarder) setTarget(rid string) {
	f.mu.Lock()
	changed := rid != f.target
	f.target = rid
	ask := ""
	if changed && rid != "" && rid != f.cur && !f.paused {
		ask = f.shouldAskLocked(rid)
	}
	f.mu.Unlock()
	if ask != "" && f.askKeyframe != nil {
		f.askKeyframe(ask)
	}
}

// setPaused stops or resumes forwarding without losing the numbering. A resume
// waits for a keyframe, because the subscriber's decoder missed frames.
func (f *forwarder) setPaused(p bool) {
	f.mu.Lock()
	if f.paused == p {
		f.mu.Unlock()
		return
	}
	f.paused = p
	ask := ""
	if !p {
		f.cur = "" // force the keyframe path
		if f.target != "" {
			ask = f.shouldAskLocked(f.target)
		}
	}
	f.mu.Unlock()
	if ask != "" && f.askKeyframe != nil {
		f.askKeyframe(ask)
	}
}

// keyframeWanted is called when the subscriber's decoder asks for a keyframe
// (PLI or FIR) or reports loss it cannot repair.
func (f *forwarder) keyframeWanted() {
	f.mu.Lock()
	rid := f.cur
	if rid == "" {
		rid = f.target
	}
	ask := ""
	if rid != "" {
		ask = f.shouldAskLocked(rid)
	}
	f.mu.Unlock()
	if ask != "" && f.askKeyframe != nil {
		f.askKeyframe(ask)
	}
}

// expectKeyframe marks the subscriber's picture as damaged: it asks for a
// keyframe now and again each time the publisher's packets arrive, until one does.
func (f *forwarder) expectKeyframe() {
	f.mu.Lock()
	f.needKey, f.needUntil = true, f.now().Add(keyframeRecoveryWindow)
	rid := f.cur
	if rid == "" {
		rid = f.target
	}
	ask := ""
	if rid != "" && !f.paused {
		ask = f.shouldAskLocked(rid)
	}
	f.mu.Unlock()
	if ask != "" && f.askKeyframe != nil {
		f.askKeyframe(ask)
	}
}

func (f *forwarder) shouldAskLocked(rid string) string {
	now := f.now()
	if now.Sub(f.lastAsk) < keyframeAskInterval {
		return ""
	}
	f.lastAsk = now
	return rid
}

// push offers a packet that arrived on layer rid. It never modifies pkt, which
// every subscriber of the track shares.
func (f *forwarder) push(rid string, pkt *rtp.Packet) {
	f.mu.Lock()
	if f.paused || f.target == "" {
		f.mu.Unlock()
		return
	}
	if rid != f.cur {
		if rid != f.target {
			f.mu.Unlock()
			return
		}
		if !f.codec.keyframe(pkt.Payload) {
			ask := f.shouldAskLocked(rid)
			f.mu.Unlock()
			if ask != "" && f.askKeyframe != nil {
				f.askKeyframe(ask)
			}
			return
		}
		f.switchLocked(rid, pkt)
	}

	// Damage and recovery. A burst of missing packets marks the picture damaged;
	// a damaged picture is repaired only by a keyframe, which is asked for every
	// time a packet arrives until one does.
	recoverAsk := ""
	if rid == f.cur {
		if f.seenIn {
			if g := int16(pkt.SequenceNumber - f.lastIn - 1); g >= gapBurst && g < 3000 {
				f.needKey, f.needUntil = true, f.now().Add(keyframeRecoveryWindow)
			}
		}
		if !f.seenIn || int16(pkt.SequenceNumber-f.lastIn) > 0 {
			f.lastIn, f.seenIn = pkt.SequenceNumber, true
		}
		if f.needKey {
			switch {
			case f.now().After(f.needUntil), f.codec.keyframe(pkt.Payload):
				f.needKey = false
			default:
				recoverAsk = f.shouldAskLocked(rid)
			}
		}
	}

	d, hasDesc := f.codec.describe(pkt.Payload)
	out := &rtp.Packet{Header: pkt.Header, Payload: pkt.Payload}
	// The publisher's header extensions (rid, mid, its own transport-wide
	// sequence number) belong to its session; this subscriber negotiated its own.
	out.Header.Extension, out.Header.Extensions = false, nil
	out.SequenceNumber = pkt.SequenceNumber + f.seqOff
	out.Timestamp = pkt.Timestamp + f.tsOff
	if hasDesc && (d.hasPic || d.hasTL0) && (f.picOff != 0 || f.tl0Off != 0) {
		out.Payload = vp8Rewrite(pkt.Payload, d, f.picOff, f.tl0Off)
	}
	f.lastSeq, f.lastTS = out.SequenceNumber, out.Timestamp
	if hasDesc && d.hasPic {
		mask := uint16(0x7F)
		if d.pic15 {
			mask = 0x7FFF
		}
		f.lastPic = (d.pic + f.picOff) & mask
	}
	if hasDesc && d.hasTL0 {
		f.lastTL0 = d.tl0 + f.tl0Off
	}
	f.lastWrite = f.now()
	// Hand the write lock over before releasing the state lock, so packets leave
	// in the order they were numbered while other layers' readers are not held up
	// by the I/O itself.
	f.wmu.Lock()
	f.mu.Unlock()

	f.sentBytes.Add(uint64(len(pkt.Payload)))
	// A write fails while the subscriber's transport is down; the packet is just
	// dropped and forwarding resumes by itself when it is back.
	_ = f.out.WriteRTP(out)
	f.wmu.Unlock()
	if recoverAsk != "" && f.askKeyframe != nil {
		f.askKeyframe(recoverAsk)
	}
}

// switchLocked moves to layer rid at the keyframe pkt, choosing offsets so the
// first packet continues the numbering of the last one forwarded.
func (f *forwarder) switchLocked(rid string, pkt *rtp.Packet) {
	if !f.started {
		f.started = true
	} else {
		f.seqOff = f.lastSeq + 1 - pkt.SequenceNumber
		// RTP time moves with the wall clock between layers, whose own
		// timestamps are unrelated. At least one tick, so it never repeats.
		ticks := uint32(f.now().Sub(f.lastWrite).Seconds() * 90000)
		if ticks < 1 {
			ticks = 1
		}
		f.tsOff = f.lastTS + ticks - pkt.Timestamp
		if d, ok := f.codec.describe(pkt.Payload); ok {
			if d.hasPic {
				mask := uint16(0x7F)
				if d.pic15 {
					mask = 0x7FFF
				}
				f.picOff = (f.lastPic + 1 - d.pic) & mask
			}
			if d.hasTL0 {
				f.tl0Off = f.lastTL0 + 1 - d.tl0
			}
		}
	}
	if f.cur != rid {
		f.switches++
	}
	f.cur = rid
	f.seenIn = false  // a layer is its own stream, with its own numbering
	f.needKey = false // this packet is the keyframe
}

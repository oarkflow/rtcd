package sfu

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtp"
)

// layerSink is one subscriber's view of one published video track. forwarder
// serves simulcast (separate streams per layer) and svcForwarder serves SVC
// (spatial layers inside one stream).
type layerSink interface {
	push(rid string, pkt *rtp.Packet)
	setTarget(rid string)
	setPaused(bool)
	state() layerState
	keyframeWanted()
	expectKeyframe()
}

var (
	_ layerSink = (*forwarder)(nil)
	_ layerSink = (*svcForwarder)(nil)
)

// svcForwarder forwards a VP9 SVC stream: one SSRC whose packets each belong to
// a spatial layer (SID 0, 1, 2 are the sizes "q", "h", "f"). A subscriber gets
// every packet up to its layer; the rest are dropped, which is the whole of
// "choosing a quality".
//
// What makes dropping safe:
//   - sequence numbers are renumbered so the subscriber sees no gaps (a gap is
//     how a receiver detects loss, and it would ask for packets that were
//     deliberately never sent);
//   - the last forwarded packet of each frame carries the marker bit, because
//     the encoder set it only on the top layer's last packet, and the receiver
//     uses it to know a picture is complete;
//   - going down takes effect at the start of the next picture, going up only
//     at a keyframe (a higher layer predicted from frames the subscriber was
//     never sent could not be decoded).
//
// Packets that arrive late from the publisher (after a later one was already
// forwarded) are not forwarded: they could not be renumbered into place. On a
// healthy upstream that never happens; on a lossy one the subscriber asks for a
// keyframe and recovers.
type svcForwarder struct {
	out         rtpWriter
	askKeyframe func(rid string)
	now         func() time.Time

	wmu sync.Mutex // writes leave in numbering order

	mu       sync.Mutex
	target   int // highest spatial layer wanted; -1 forwards nothing
	cur      int // highest layer being forwarded; -1 until the first keyframe
	paused   bool
	started  bool
	seqOff   uint16
	lastIn   uint16
	lastOut  uint16
	seenIn   bool
	lastAsk  time.Time
	switches int

	// See forwarder: asking for a keyframe until one arrives after damage.
	needKey   bool
	needUntil time.Time

	sentBytes atomic.Uint64
}

func newSVCForwarder(out rtpWriter, ask func(rid string), now func() time.Time) *svcForwarder {
	if now == nil {
		now = time.Now
	}
	return &svcForwarder{out: out, askKeyframe: ask, now: now, target: -1, cur: -1}
}

var sidNames = [...]string{"q", "h", "f"}

func sidOf(rid string) int {
	for i, n := range sidNames {
		if n == rid {
			return i
		}
	}
	return -1
}

func ridOfSID(sid int) string {
	if sid >= 0 && sid < len(sidNames) {
		return sidNames[sid]
	}
	return ""
}

func (f *svcForwarder) state() layerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return layerState{Cur: ridOfSID(f.cur), Target: ridOfSID(f.target), Paused: f.paused, Switches: f.switches}
}

func (f *svcForwarder) setTarget(rid string) {
	f.mu.Lock()
	t := sidOf(rid)
	changed := t != f.target
	f.target = t
	ask := changed && t > f.cur && !f.paused && f.askLocked()
	f.mu.Unlock()
	if ask && f.askKeyframe != nil {
		f.askKeyframe("q") // the keyframe is on the base layer
	}
}

func (f *svcForwarder) setPaused(p bool) {
	f.mu.Lock()
	if f.paused == p {
		f.mu.Unlock()
		return
	}
	f.paused = p
	ask := false
	if !p {
		f.cur = -1 // wait for a keyframe: the decoder missed pictures
		ask = f.target >= 0 && f.askLocked()
	}
	f.mu.Unlock()
	if ask && f.askKeyframe != nil {
		f.askKeyframe("q")
	}
}

func (f *svcForwarder) keyframeWanted() {
	f.mu.Lock()
	ask := f.askLocked()
	f.mu.Unlock()
	if ask && f.askKeyframe != nil {
		f.askKeyframe("q")
	}
}

// expectKeyframe marks the subscriber's picture as damaged: it asks for a
// keyframe now and again each time the publisher's packets arrive, until one does.
func (f *svcForwarder) expectKeyframe() {
	f.mu.Lock()
	f.needKey, f.needUntil = true, f.now().Add(keyframeRecoveryWindow)
	ask := !f.paused && f.askLocked()
	f.mu.Unlock()
	if ask && f.askKeyframe != nil {
		f.askKeyframe("q")
	}
}

func (f *svcForwarder) askLocked() bool {
	now := f.now()
	if now.Sub(f.lastAsk) < keyframeAskInterval {
		return false
	}
	f.lastAsk = now
	return true
}

// push offers a packet of spatial layer rid.
func (f *svcForwarder) push(rid string, pkt *rtp.Packet) {
	sid := sidOf(rid)
	d, ok := parseVP9(pkt.Payload)
	f.mu.Lock()
	if !ok || sid < 0 || f.paused || f.target < 0 {
		f.mu.Unlock()
		return
	}
	if f.seenIn && int16(pkt.SequenceNumber-f.lastIn) <= 0 {
		f.mu.Unlock() // late or duplicate: it cannot be renumbered into place
		return
	}
	ask := false
	key := d.start && !d.inter && sid == 0
	if f.seenIn {
		if g := int16(pkt.SequenceNumber - f.lastIn - 1); g >= gapBurst && g < 3000 {
			f.needKey, f.needUntil = true, f.now().Add(keyframeRecoveryWindow)
		}
	}
	if f.needKey {
		switch {
		case f.now().After(f.needUntil), key:
			f.needKey = false
		case sid == 0 && d.start:
			ask = f.askLocked()
		}
	}
	switch {
	case f.cur < 0:
		if !key {
			ask = sid == 0 && d.start && f.askLocked()
			f.mu.Unlock()
			if ask && f.askKeyframe != nil {
				f.askKeyframe("q")
			}
			return
		}
		// First picture: start here, numbering on from whatever was sent before.
		if f.started {
			f.seqOff = f.lastOut + 1 - pkt.SequenceNumber
		}
		f.started = true
		f.cur = f.target
		f.switches++
	case d.start && sid == 0 && f.target != f.cur:
		// A picture boundary: the only place the layer may change.
		if f.target < f.cur {
			f.cur = f.target
			f.switches++
		} else if key {
			f.cur = f.target
			f.switches++
		} else {
			ask = f.askLocked()
		}
	}
	// A packet is accounted for in input order even when it is dropped, so a
	// dropped layer leaves no gap in what the subscriber receives.
	if !f.seenIn {
		f.seenIn = true
	}
	f.lastIn = pkt.SequenceNumber
	if sid > f.cur {
		f.seqOff--
		f.mu.Unlock()
		if ask && f.askKeyframe != nil {
			f.askKeyframe("q")
		}
		return
	}
	out := &rtp.Packet{Header: pkt.Header, Payload: pkt.Payload}
	out.Header.Extension, out.Header.Extensions = false, nil
	out.SequenceNumber = pkt.SequenceNumber + f.seqOff
	if sid == f.cur && d.end {
		out.Marker = true // the picture ends here for this subscriber
	}
	f.lastOut = out.SequenceNumber
	f.wmu.Lock()
	f.mu.Unlock()
	f.sentBytes.Add(uint64(len(pkt.Payload)))
	_ = f.out.WriteRTP(out)
	f.wmu.Unlock()
	if ask && f.askKeyframe != nil {
		f.askKeyframe("q")
	}
}

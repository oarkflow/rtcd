package sfu

import "strings"

// Video codecs the SFU forwards. What differs between them is only what a layer
// switch needs to know: where a keyframe starts, and where the picture counters
// live (so they can be renumbered). Everything else about forwarding is shared.

type codecKind uint8

const (
	codecVP8 codecKind = iota
	codecVP9
	codecH264
)

func codecOf(mime string) (codecKind, bool) {
	switch strings.ToLower(mime) {
	case "video/vp8":
		return codecVP8, true
	case "video/vp9":
		return codecVP9, true
	case "video/h264":
		return codecH264, true
	}
	return 0, false
}

func (c codecKind) String() string {
	switch c {
	case codecVP9:
		return "vp9"
	case codecH264:
		return "h264"
	}
	return "vp8"
}

// describe parses the picture counters of a payload (VP8 and VP9). H.264 has
// none, so it reports false and its payloads are forwarded untouched.
func (c codecKind) describe(payload []byte) (vp8Desc, bool) {
	switch c {
	case codecVP8:
		return parseVP8(payload)
	case codecVP9:
		d, ok := parseVP9(payload)
		return d.vp8Desc, ok
	}
	return vp8Desc{}, false
}

// keyframe reports whether the payload begins a picture a decoder can start from.
func (c codecKind) keyframe(payload []byte) bool {
	switch c {
	case codecVP8:
		return isVP8Keyframe(payload)
	case codecVP9:
		return isVP9Keyframe(payload)
	case codecH264:
		return isH264Keyframe(payload)
	}
	return false
}

// ---------------------------------------------------------------------------
// H.264 (RFC 6184)
// ---------------------------------------------------------------------------

// isH264Keyframe reports whether the packet starts a keyframe access unit: a
// sequence parameter set, alone or inside a STAP-A. A decoder joining at an
// IDR picture without its SPS and PPS could not decode it, and encoders send
// them directly before each IDR, so the SPS is the point to switch at.
func isH264Keyframe(p []byte) bool {
	if len(p) < 1 {
		return false
	}
	switch p[0] & 0x1F {
	case 7: // SPS
		return true
	case 24: // STAP-A: size-prefixed NAL units
		i := 1
		for i+2 < len(p) {
			size := int(p[i])<<8 | int(p[i+1])
			i += 2
			if size == 0 || i+size > len(p) {
				return false
			}
			if p[i]&0x1F == 7 {
				return true
			}
			i += size
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// VP9 (RFC 9628 payload descriptor)
// ---------------------------------------------------------------------------
//
//	  0 1 2 3 4 5 6 7
//	 +-+-+-+-+-+-+-+-+
//	 |I|P|L|F|B|E|V|Z|   required
//	 +-+-+-+-+-+-+-+-+
//	 |M| PictureID   |   if I (15 bits when M)
//	 | TID |U| SID |D|   if L
//	 |   TL0PICIDX   |   if L and not F
//	 |    P_DIFF   |N|   if F and P (repeats while N)
//	 | scalability structure |  if V

type vp9Desc struct {
	vp8Desc          // shared fields: picture id, TL0PICIDX and their positions; start = B
	inter      bool  // P: predicted from an earlier picture
	end        bool  // E: last packet of this layer's frame
	hasLayer   bool  // L
	flexible   bool  // F
	tid, sid   uint8 // temporal and spatial layer
	switchUp   bool  // U: switching up to this temporal layer is possible here
	interLayer bool  // D: depends on the layer below in the same picture
	markerless bool  // reserved
}

func parseVP9(p []byte) (vp9Desc, bool) {
	var d vp9Desc
	if len(p) < 1 {
		return d, false
	}
	b := p[0]
	i := 1
	d.inter = b&0x40 != 0
	d.hasLayer = b&0x20 != 0
	d.flexible = b&0x10 != 0
	d.start = b&0x08 != 0
	d.end = b&0x04 != 0
	if b&0x80 != 0 { // I
		if len(p) <= i {
			return d, false
		}
		d.hasPic, d.picPos = true, i
		if p[i]&0x80 != 0 {
			if len(p) <= i+1 {
				return d, false
			}
			d.pic15 = true
			d.pic = uint16(p[i]&0x7F)<<8 | uint16(p[i+1])
			i += 2
		} else {
			d.pic = uint16(p[i] & 0x7F)
			i++
		}
	}
	if d.hasLayer { // L
		if len(p) <= i {
			return d, false
		}
		l := p[i]
		d.tid, d.switchUp, d.sid, d.interLayer = l>>5, l&0x10 != 0, (l>>1)&0x07, l&0x01 != 0
		i++
		if !d.flexible { // TL0PICIDX follows in non-flexible mode
			if len(p) <= i {
				return d, false
			}
			d.hasTL0, d.tl0, d.tl0Pos = true, p[i], i
			i++
		}
	}
	d.size = i
	return d, true
}

// isVP9Keyframe: the first packet of a picture that is not predicted from an
// earlier one, at the base spatial layer.
func isVP9Keyframe(p []byte) bool {
	d, ok := parseVP9(p)
	return ok && d.start && !d.inter && (!d.hasLayer || d.sid == 0)
}

package sfu

// VP8 RTP payload descriptor (RFC 7741), just enough to forward simulcast:
// find the keyframes a layer switch must wait for, and keep the picture id and
// TL0PICIDX counters continuous across a switch. A receiver uses those counters
// to order and reference frames, so a switch that makes them jump backwards or
// forwards stalls the decoder even though every packet arrived.
//
//	  0 1 2 3 4 5 6 7
//	 +-+-+-+-+-+-+-+-+
//	 |X|R|N|S|R| PID |   required
//	 +-+-+-+-+-+-+-+-+
//	 |I|L|T|K| RSV   |   present when X
//	 +-+-+-+-+-+-+-+-+
//	 |M| PictureID   |   present when I; 15 bits when M
//	 +-+-+-+-+-+-+-+-+
//	 |   TL0PICIDX   |   present when L
//	 +-+-+-+-+-+-+-+-+
//	 |TID|Y| KEYIDX  |   present when T or K

type vp8Desc struct {
	start  bool  // S: first packet of a partition
	pid    uint8 // partition index
	hasPic bool
	pic15  bool // PictureID is 15 bits, else 7
	pic    uint16
	picPos int
	hasTL0 bool
	tl0    uint8
	tl0Pos int
	size   int // descriptor length; the VP8 payload starts here
}

// parseVP8 reads the descriptor of an RTP payload.
func parseVP8(p []byte) (vp8Desc, bool) {
	var d vp8Desc
	if len(p) < 1 {
		return d, false
	}
	b := p[0]
	x := b&0x80 != 0
	d.start = b&0x10 != 0
	d.pid = b & 0x0F
	i := 1
	if x {
		if len(p) < 2 {
			return d, false
		}
		ext := p[1]
		i = 2
		if ext&0x80 != 0 { // I: PictureID
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
		if ext&0x40 != 0 { // L: TL0PICIDX
			if len(p) <= i {
				return d, false
			}
			d.hasTL0, d.tl0, d.tl0Pos = true, p[i], i
			i++
		}
		if ext&0x30 != 0 { // T or K: TID/KEYIDX byte
			if len(p) <= i {
				return d, false
			}
			i++
		}
	}
	d.size = i
	return d, len(p) >= i
}

// isVP8Keyframe reports whether the packet starts a keyframe: the first packet
// of partition 0, whose first payload byte has the P (non-key) bit clear.
func isVP8Keyframe(p []byte) bool {
	d, ok := parseVP8(p)
	if !ok || !d.start || d.pid != 0 || len(p) <= d.size {
		return false
	}
	return p[d.size]&0x01 == 0
}

// vp8Rewrite returns a copy of payload with the picture id and TL0PICIDX moved
// by the given offsets (modulo their widths). The caller's payload, shared by
// every subscriber, is never modified.
func vp8Rewrite(payload []byte, d vp8Desc, picOff uint16, tl0Off uint8) []byte {
	out := make([]byte, len(payload))
	copy(out, payload)
	if d.hasPic {
		if d.pic15 {
			v := (d.pic + picOff) & 0x7FFF
			out[d.picPos] = 0x80 | byte(v>>8)
			out[d.picPos+1] = byte(v)
		} else {
			out[d.picPos] = byte((d.pic + picOff) & 0x7F)
		}
	}
	if d.hasTL0 {
		out[d.tl0Pos] = d.tl0 + tl0Off
	}
	return out
}

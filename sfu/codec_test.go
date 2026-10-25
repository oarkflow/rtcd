package sfu

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4/pkg/media/h264reader"
	"github.com/pion/webrtc/v4/pkg/media/ivfreader"
)

func encode(t *testing.T, name string, args ...string) string {
	t.Helper()
	needFFmpeg(t)
	out := filepath.Join(t.TempDir(), name)
	full := append([]string{"-y", "-v", "error", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=30", "-t", "4"}, args...)
	full = append(full, out)
	if b, err := exec.Command("ffmpeg", full...).CombinedOutput(); err != nil {
		t.Skipf("ffmpeg cannot make %s here: %v\n%s", name, err, b)
	}
	return out
}

// TestH264KeyframeDetectionMatchesRealEncoderOutput packetizes a real x264
// stream and checks that exactly the access units that begin with an IDR (the
// encoder's own keyframes) are reported as places a layer switch may happen.
func TestH264KeyframeDetectionMatchesRealEncoderOutput(t *testing.T) {
	path := encode(t, "v.h264", "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-g", "30",
		"-x264-params", "keyint=30:min-keyint=30:scenecut=0:repeat-headers=1:slices=1", "-bsf:v", "h264_mp4toannexb", "-f", "h264")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := h264reader.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	type au struct {
		data []byte
		idr  bool
	}
	var units []au
	var cur au
	flush := func() {
		if len(cur.data) > 0 {
			units = append(units, cur)
		}
		cur = au{}
	}
	for {
		nal, err := r.NextNAL()
		if err != nil {
			break
		}
		kind := nal.UnitType
		if kind == h264reader.NalUnitTypeSPS || kind == h264reader.NalUnitTypeCodedSliceNonIdr || kind == h264reader.NalUnitTypeAUD {
			flush() // a new access unit begins
		}
		cur.data = append(cur.data, 0, 0, 0, 1)
		cur.data = append(cur.data, nal.Data...)
		if kind == h264reader.NalUnitTypeCodedSliceIdr {
			cur.idr = true
		}
	}
	flush()
	if len(units) < 60 {
		t.Fatalf("only %d access units parsed", len(units))
	}
	pay := &codecs.H264Payloader{}
	wantKeys, gotKeys := 0, 0
	for i, u := range units {
		pkts := pay.Payload(1200, u.data)
		flagged := 0
		for _, p := range pkts {
			if isH264Keyframe(p) {
				flagged++
			}
		}
		if u.idr {
			wantKeys++
			if flagged != 1 {
				t.Fatalf("access unit %d is a keyframe but %d of its %d packets are reported as switch points (want exactly 1)", i, flagged, len(pkts))
			}
			if !isH264Keyframe(pkts[0]) {
				t.Fatalf("access unit %d: the switch point is not the first packet; a viewer switching there would miss the parameter sets", i)
			}
			gotKeys++
		} else if flagged != 0 {
			t.Fatalf("access unit %d is a delta frame but %d packets are reported as switch points", i, flagged)
		}
	}
	if wantKeys < 3 || gotKeys != wantKeys {
		t.Fatalf("%d keyframes in the stream, %d detected", wantKeys, gotKeys)
	}
}

func TestH264DetectionOnHandBuiltPackets(t *testing.T) {
	sps := []byte{0x67, 0x42, 0xe0, 0x1f}
	pps := []byte{0x68, 0xce, 0x3c, 0x80}
	stap := []byte{24}
	for _, n := range [][]byte{sps, pps} {
		stap = append(stap, byte(len(n)>>8), byte(len(n)))
		stap = append(stap, n...)
	}
	for name, tc := range map[string]struct {
		p    []byte
		want bool
	}{
		"single SPS":         {sps, true},
		"STAP-A with SPS":    {stap, true},
		"PPS alone":          {pps, false},
		"IDR slice, no SPS":  {[]byte{0x65, 0x88, 0x84}, false},
		"non-IDR slice":      {[]byte{0x41, 0x9a, 0x00}, false},
		"FU-A fragment":      {[]byte{0x7c, 0x85, 0x01}, false},
		"empty":              {nil, false},
		"truncated STAP-A":   {[]byte{24, 0, 9, 0x67}, false},
		"zero-length STAP-A": {[]byte{24, 0, 0}, false},
	} {
		if got := isH264Keyframe(tc.p); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// refVP9IsKey reads the frame type from the VP9 bitstream itself.
// The first byte is frame_marker(2) profile_low(1) profile_high(1)
// [reserved(1) when profile is 3] show_existing_frame(1) frame_type(1) ...,
// most significant bit first; frame_type 0 is a keyframe.
func refVP9IsKey(frame []byte) bool {
	if len(frame) < 1 || frame[0]>>6 != 2 {
		return false
	}
	profile := (frame[0]>>5)&1 | ((frame[0]>>4)&1)<<1
	existing, kind := uint(3), uint(2)
	if profile == 3 {
		existing, kind = 2, 1
	}
	if (frame[0]>>existing)&1 == 1 {
		return false // shows an earlier frame: not a new picture
	}
	return (frame[0]>>kind)&1 == 0
}

func TestVP9KeyframeDetectionMatchesRealEncoderOutput(t *testing.T) {
	path := encode(t, "v.ivf", "-c:v", "libvpx-vp9", "-b:v", "300k", "-g", "30", "-deadline", "realtime", "-cpu-used", "8", "-f", "ivf")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, _, err := ivfreader.NewWith(f)
	if err != nil {
		t.Fatal(err)
	}
	pay := &codecs.VP9Payloader{InitialPictureIDFn: func() uint16 { return 100 }}
	keys, frames := 0, 0
	for {
		frame, _, err := r.ParseNextFrame()
		if err != nil {
			break
		}
		frames++
		want := refVP9IsKey(frame)
		pkts := pay.Payload(1000, bytes.Clone(frame))
		flagged := 0
		for _, p := range pkts {
			if isVP9Keyframe(p) {
				flagged++
			}
		}
		if want {
			keys++
		}
		if (want && flagged != 1) || (!want && flagged != 0) {
			t.Fatalf("frame %d: keyframe=%v but %d of %d packets flagged", frames, want, flagged, len(pkts))
		}
		if want && !isVP9Keyframe(pkts[0]) {
			t.Fatalf("frame %d: keyframe not flagged on its first packet", frames)
		}
		// The counters are found where they are, so they can be renumbered.
		if d, ok := parseVP9(pkts[0]); !ok || !d.hasPic {
			t.Fatalf("frame %d: picture id not parsed from %x", frames, pkts[0][:4])
		}
	}
	if frames < 60 || keys < 3 {
		t.Fatalf("%d frames, %d keyframes", frames, keys)
	}
}

func TestVP9DescriptorParsing(t *testing.T) {
	// I=1 P=0 L=1 F=0 B=1 E=0, 15-bit picture id 0x1234, TID=2 U=1 SID=1 D=1, TL0=7
	p := []byte{0x80 | 0x20 | 0x08, 0x80 | 0x12, 0x34, 2<<5 | 1<<4 | 1<<1 | 1, 7, 0xAA}
	d, ok := parseVP9(p)
	if !ok || !d.hasPic || !d.pic15 || d.pic != 0x1234 || d.sid != 1 || d.tid != 2 || !d.switchUp || !d.interLayer || !d.hasTL0 || d.tl0 != 7 || !d.start || d.inter || d.end {
		t.Fatalf("%+v ok=%v", d, ok)
	}
	if isVP9Keyframe(p) {
		t.Fatal("a spatial layer above the base cannot start a keyframe")
	}
	p[3] = 2<<5 | 1<<4 // SID 0
	if !isVP9Keyframe(p) {
		t.Fatal("base layer, not predicted, start of picture: that is a keyframe")
	}
	// The renumbering keeps the 15-bit format.
	out := vp8Rewrite(p, mustVP9(t, p).vp8Desc, 5, 3)
	if d2, _ := parseVP9(out); d2.pic != 0x1239 || d2.tl0 != 10 {
		t.Fatalf("rewritten: pic %x tl0 %d", d2.pic, d2.tl0)
	}
	for _, bad := range [][]byte{nil, {0x80}, {0x80, 0x80}, {0x20}, {0x20 | 0x80, 0x01}} {
		if _, ok := parseVP9(bad); ok {
			t.Fatalf("accepted truncated descriptor %x", bad)
		}
	}
}

func mustVP9(t *testing.T, p []byte) vp9Desc {
	d, ok := parseVP9(p)
	if !ok {
		t.Fatal("not parsed")
	}
	return d
}

func TestCodecLookup(t *testing.T) {
	for mime, want := range map[string]codecKind{"video/VP8": codecVP8, "video/vp9": codecVP9, "VIDEO/H264": codecH264} {
		if got, ok := codecOf(mime); !ok || got != want {
			t.Errorf("%s -> %v %v", mime, got, ok)
		}
	}
	if _, ok := codecOf("video/AV1"); ok {
		t.Error("AV1 is not supported and must not be claimed")
	}
}

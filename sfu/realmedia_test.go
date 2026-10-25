package sfu

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media/ivfreader"
	"github.com/pion/webrtc/v4/pkg/media/oggreader"
)

// Real encoded media for the tests that must prove something plays: ffmpeg
// makes a few seconds of VP8 video (a moving test pattern, a keyframe every
// second) and Opus audio (a tone), which are then sent through the SFU as a
// browser would send them.

func needFFmpeg(t *testing.T) {
	t.Helper()
	for _, b := range []string{"ffmpeg", "ffprobe"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s is not installed", b)
		}
	}
}

func runCmd(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, errb.String())
	}
	return out.Bytes()
}

var (
	mediaOnce  sync.Once
	vp8Frames  [][]byte
	opusFrames [][]byte
	mediaErr   error
)

// realMedia returns decoded-from-file frames: VP8 frames (30 fps) and Opus
// packets (20 ms).
func realMedia(t *testing.T) ([][]byte, [][]byte) {
	t.Helper()
	needFFmpeg(t)
	mediaOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sfu-media")
		if err != nil {
			mediaErr = err
			return
		}
		ivf, ogg := filepath.Join(dir, "v.ivf"), filepath.Join(dir, "a.ogg")
		for _, c := range [][]string{
			{"-y", "-v", "error", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=30", "-t", "4", "-c:v", "libvpx", "-b:v", "300k", "-g", "30", "-deadline", "realtime", "-cpu-used", "8", "-an", "-f", "ivf", ivf},
			{"-y", "-v", "error", "-f", "lavfi", "-i", "sine=frequency=440:duration=4", "-c:a", "libopus", "-b:a", "32k", "-ar", "48000", "-ac", "2", "-frame_duration", "20", "-page_duration", "20000", "-f", "ogg", ogg},
		} {
			if out, err := exec.Command("ffmpeg", c...).CombinedOutput(); err != nil {
				mediaErr = &exec.ExitError{Stderr: out}
				return
			}
		}
		if f, err := os.Open(ivf); err == nil {
			r, _, err := ivfreader.NewWith(f)
			for err == nil {
				var fr []byte
				fr, _, err = r.ParseNextFrame()
				if err == nil {
					vp8Frames = append(vp8Frames, append([]byte(nil), fr...))
				}
			}
			f.Close()
		}
		if f, err := os.Open(ogg); err == nil {
			r, _, err := oggreader.NewWith(f)
			for err == nil {
				var pg []byte
				pg, _, err = r.ParseNextPage()
				if err == nil && !bytes.HasPrefix(pg, []byte("OpusHead")) && !bytes.HasPrefix(pg, []byte("OpusTags")) {
					opusFrames = append(opusFrames, append([]byte(nil), pg...))
				}
			}
			f.Close()
		}
		_ = os.RemoveAll(dir)
	})
	if mediaErr != nil || len(vp8Frames) < 60 || len(opusFrames) < 100 {
		t.Fatalf("could not make test media: %v (%d video frames, %d audio packets)", mediaErr, len(vp8Frames), len(opusFrames))
	}
	return vp8Frames, opusFrames
}

// startRealCamera publishes the test video as simulcast layers (the same picture
// on each), looping, with everything a browser would put on the packets.
func (c *client) startRealCamera(rids ...string) {
	c.h.t.Helper()
	frames, _ := realMedia(c.h.t)
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
	}
	for _, rid := range rids {
		rid := rid
		go func() {
			for {
				if _, _, err := sender.ReadSimulcastRTCP(rid); err != nil {
					return
				}
			}
		}()
	}
	stop := make(chan struct{})
	c.h.t.Cleanup(func() { close(stop) })
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
	for i, rid := range rids {
		i, rid := i, rid
		go func() {
			pay := &codecs.VP8Payloader{EnablePictureID: true}
			seq := uint16(1000 * (i + 1))
			ts := uint32(500000 * (i + 1))
			n := 0
			tick := time.NewTicker(33 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
				e := findExt()
				if e == nil {
					continue
				}
				frame := frames[n%len(frames)]
				n++
				ts += 3000
				parts := pay.Payload(1100, frame)
				for j, part := range parts {
					seq++
					h := rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts, Marker: j == len(parts)-1}
					_ = h.SetExtension(e.midID, []byte(e.mid))
					_ = h.SetExtension(e.ridID, []byte(rid))
					_ = tracks[rid].WriteRTP(&rtp.Packet{Header: h, Payload: part})
				}
			}
		}()
	}
}

// startRealMic publishes the test audio, tagged with a speaking loudness.
func (c *client) startRealMic() {
	c.h.t.Helper()
	_, packets := realMedia(c.h.t)
	tr, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "mic", "s-"+c.user)
	if err != nil {
		c.h.t.Fatal(err)
	}
	sender, err := c.pc.AddTrack(tr)
	if err != nil {
		c.h.t.Fatal(err)
	}
	go func() {
		for {
			if _, _, err := sender.ReadRTCP(); err != nil {
				return
			}
		}
	}()
	stop := make(chan struct{})
	c.h.t.Cleanup(func() { close(stop) })
	go func() {
		seq, ts, n := uint16(1), uint32(0), 0
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
				continue
			}
			seq++
			ts += 960
			h := rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts}
			_ = h.SetExtension(id, []byte{0x80 | 30})
			_ = tr.WriteRTP(&rtp.Packet{Header: h, Payload: packets[n%len(packets)]})
			n++
		}
	}()
}

// probe describes a media file as ffprobe sees it.
type probe struct {
	Streams []struct {
		CodecName string `json:"codec_name"`
		CodecType string `json:"codec_type"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
		Frames    string `json:"nb_read_frames"`
		Duration  string `json:"duration"`
	} `json:"streams"`
}

func ffprobe(t *testing.T, path string) probe {
	t.Helper()
	out := runCmd(t, "ffprobe", "-v", "error", "-count_frames", "-show_streams", "-of", "json", path)
	var p probe
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// decodes proves a file plays: ffmpeg decodes all of it without a single error.
func decodes(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command("ffmpeg", "-v", "error", "-i", path, "-f", "null", "-")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil || strings.TrimSpace(errb.String()) != "" {
		t.Fatalf("%s does not decode cleanly: %v\n%s", filepath.Base(path), err, errb.String())
	}
}

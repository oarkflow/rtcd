package sfu

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/at-wat/ebml-go/mkvcore"
	"github.com/at-wat/ebml-go/webm"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4/pkg/media/samplebuilder"
)

// Recording.
//
// A recording is one WebM file (VP8 video, Opus audio) per participant, not a
// mixed composite: mixing means decoding and re-encoding everyone, which an SFU
// exists to avoid. Merge or lay them out afterwards (ffmpeg does it in a line).
//
// The recorder is a hidden subscriber. It takes each participant's video
// through the same layer forwarder viewers use, always on the best layer that is
// live, so a publisher whose top layer drops is still recorded, at lower
// quality, without a gap. Everyone in the call is told it is being recorded.

// Errors.
var (
	ErrRecordingDisabled = errors.New("sfu: recording is not enabled on this server")
	ErrRecording         = errors.New("sfu: the room is already being recorded")
	ErrNotRecording      = errors.New("sfu: the room is not being recorded")
	ErrDiskFull          = errors.New("sfu: not enough free disk space to record")
	// ErrRecordingE2EE: the server holds only ciphertext of an encrypted call.
	ErrRecordingE2EE = errors.New("sfu: an end-to-end encrypted call cannot be recorded by the server, which never has the keys")
)

// RecordingInfo describes a recording.
type RecordingInfo struct {
	ID        string          `json:"id"`
	Room      string          `json:"room"`
	StartedBy string          `json:"started_by"`
	StartedAt time.Time       `json:"started_at"`
	StoppedAt *time.Time      `json:"stopped_at,omitempty"`
	Files     []RecordingFile `json:"files"`
}

// RecordingFile is one participant's recording.
type RecordingFile struct {
	User      string    `json:"user"`
	Path      string    `json:"path"`
	StartedAt time.Time `json:"started_at"`
	Video     bool      `json:"video"`
	Audio     bool      `json:"audio"`
}

// RecordingNotifier is an optional extra for a Signaler: it is told when a
// room's recording starts or stops, and which participants to tell.
type RecordingNotifier interface {
	Recording(room string, on bool, by string, participants []string) error
}

var unsafePath = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string {
	s = unsafePath.ReplaceAllString(s, "_")
	if s == "" || s == "." || s == ".." {
		return "_"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

type recording struct {
	info  RecordingInfo
	dir   string
	mu    sync.Mutex
	parts map[string]*partRec // by participant
	pubs  map[string]*recPub  // by published track id
}

// recPub is one published track being recorded.
type recPub struct {
	pub   *published
	part  *partRec
	video layerSink
	tap   *tap
}

// StartRecording begins recording a room. by names who asked (the caller checks
// they may).
func (s *Server) StartRecording(roomID, by string) (RecordingInfo, error) {
	if s.cfg.RecordDir == "" {
		return RecordingInfo{}, ErrRecordingDisabled
	}
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return RecordingInfo{}, ErrNoPeer
	}
	if r.e2ee.Load() {
		return RecordingInfo{}, ErrRecordingE2EE
	}
	if s.cfg.RecordMinFree > 0 {
		if free, ok := freeBytes(s.cfg.RecordDir); ok && free < s.cfg.RecordMinFree {
			return RecordingInfo{}, ErrDiskFull
		}
	}
	now := time.Now().UTC()
	rec := &recording{
		dir:   filepath.Join(s.cfg.RecordDir, safeName(roomID), now.Format("20060102T150405Z")),
		parts: map[string]*partRec{}, pubs: map[string]*recPub{},
		info: RecordingInfo{ID: safeName(roomID) + "-" + now.Format("20060102T150405Z"), Room: roomID, StartedBy: by, StartedAt: now},
	}
	if err := os.MkdirAll(rec.dir, 0o750); err != nil {
		return RecordingInfo{}, err
	}
	if !r.rec.CompareAndSwap(nil, rec) {
		return RecordingInfo{}, ErrRecording
	}
	r.mu.Lock()
	pubs := make([]*published, 0, len(r.pubs))
	users := make([]string, 0, len(r.peers))
	for _, pub := range r.pubs {
		pubs = append(pubs, pub)
	}
	for u, p := range r.peers {
		if !p.relay {
			users = append(users, u)
		}
	}
	r.mu.Unlock()
	for _, pub := range pubs {
		rec.attach(pub)
	}
	if n, ok := s.sig.(RecordingNotifier); ok {
		_ = n.Recording(roomID, true, by, users)
	}
	go s.watchRecording(r, rec)
	return rec.snapshot(), nil
}

// StopRecording ends a room's recording, finishes the files and returns them.
func (s *Server) StopRecording(roomID, by string) (RecordingInfo, error) {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return RecordingInfo{}, ErrNoPeer
	}
	rec := r.rec.Swap(nil)
	if rec == nil {
		return RecordingInfo{}, ErrNotRecording
	}
	info := rec.finish()
	r.mu.Lock()
	users := make([]string, 0, len(r.peers))
	for u, p := range r.peers {
		if !p.relay {
			users = append(users, u)
		}
	}
	r.mu.Unlock()
	if n, ok := s.sig.(RecordingNotifier); ok {
		_ = n.Recording(roomID, false, by, users)
	}
	return info, nil
}

// Recording reports whether a room is being recorded, and by whom.
func (s *Server) Recording(roomID string) (RecordingInfo, bool) {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return RecordingInfo{}, false
	}
	rec := r.rec.Load()
	if rec == nil {
		return RecordingInfo{}, false
	}
	return rec.snapshot(), true
}

// attach starts recording a published track.
func (rec *recording) attach(pub *published) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if _, dup := rec.pubs[pub.id]; dup || pub.owner == nil {
		return
	}
	user := pub.who
	part := rec.parts[user]
	if part == nil {
		part = &partRec{rec: rec, user: user, base: time.Now()}
		rec.parts[user] = part
	}
	rp := &recPub{pub: pub, part: part}
	if pub.kind == videoKind {
		part.setVideo(pub.vcodec, pub.svc)
		if pub.svc {
			rp.video = newSVCForwarder(videoSink{part}, pub.askKeyframe, nil)
		} else {
			rp.video = newCodecForwarder(pub.vcodec, videoSink{part}, pub.askKeyframe, nil)
		}
		pub.addSub(rp.video)
	} else {
		rp.tap = pub.addTap(part.pushAudio)
	}
	rec.pubs[pub.id] = rp
}

// detach stops recording a published track that went away. When a
// participant's last track is gone, their file is finished.
func (rec *recording) detach(pub *published) {
	rec.mu.Lock()
	rp := rec.pubs[pub.id]
	delete(rec.pubs, pub.id)
	var part *partRec
	if rp != nil {
		part = rp.part
		for _, other := range rec.pubs {
			if other.part == part {
				part = nil // still has tracks
				break
			}
		}
	}
	rec.mu.Unlock()
	if rp == nil {
		return
	}
	if rp.video != nil {
		pub.removeSub(rp.video)
	}
	if rp.tap != nil {
		pub.removeTap(rp.tap)
	}
	if part != nil {
		part.close()
	}
}

// tick keeps each recorded video on the best layer that is live.
func (rec *recording) tick(now time.Time, lowest bool) {
	rec.mu.Lock()
	rps := make([]*recPub, 0, len(rec.pubs))
	for _, rp := range rec.pubs {
		if rp.video != nil {
			rps = append(rps, rp)
		}
	}
	rec.mu.Unlock()
	for _, rp := range rps {
		best := ""
		for _, l := range rp.pub.layerInfos(now) { // lowest first
			if l.Active {
				best = l.RID
				if lowest {
					break
				}
			}
		}
		rp.video.setTarget(best)
	}
	rec.mu.Lock()
	parts := make([]*partRec, 0, len(rec.parts))
	for _, p := range rec.parts {
		parts = append(parts, p)
	}
	rec.mu.Unlock()
	for _, p := range parts {
		p.maybeStartAudioOnly(now)
	}
}

func (rec *recording) snapshot() RecordingInfo {
	rec.mu.Lock()
	parts := make([]*partRec, 0, len(rec.parts))
	for _, p := range rec.parts {
		parts = append(parts, p)
	}
	info := rec.info
	rec.mu.Unlock()
	info.Files = nil
	for _, p := range parts {
		info.Files = append(info.Files, p.files()...)
	}
	sort.Slice(info.Files, func(i, j int) bool { return info.Files[i].Path < info.Files[j].Path })
	return info
}

// finish stops everything and writes the manifest next to the files.
func (rec *recording) finish() RecordingInfo {
	rec.mu.Lock()
	rps := make([]*recPub, 0, len(rec.pubs))
	for _, rp := range rec.pubs {
		rps = append(rps, rp)
	}
	rec.pubs = map[string]*recPub{}
	parts := make([]*partRec, 0, len(rec.parts))
	for _, p := range rec.parts {
		parts = append(parts, p)
	}
	rec.mu.Unlock()
	for _, rp := range rps {
		if rp.video != nil {
			rp.pub.removeSub(rp.video)
		}
		if rp.tap != nil {
			rp.pub.removeTap(rp.tap)
		}
	}
	for _, p := range parts {
		p.close()
	}
	now := time.Now().UTC()
	rec.mu.Lock()
	rec.info.StoppedAt = &now
	rec.mu.Unlock()
	info := rec.snapshot()
	if b, err := json.MarshalIndent(info, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(rec.dir, "manifest.json"), b, 0o640)
	}
	return info
}

// ---------------------------------------------------------------------------
// One participant's file
// ---------------------------------------------------------------------------

const videoKind = 2 // webrtc.RTPCodecTypeVideo

// audioOnlyAfter is how long a participant's audio is held waiting for a video
// keyframe before the file is started without video.
const audioOnlyAfter = 2500 * time.Millisecond

type partRec struct {
	rec  *recording
	user string
	base time.Time // when this participant's recording began

	mu      sync.Mutex
	seg     int
	cur     *segment
	done    []RecordingFile
	asb     *samplebuilder.SampleBuilder
	vr      videoRec      // set when the participant's video track is attached
	pending []audioSample // audio waiting for the file to open
	firstA  time.Time
	closed  bool

	aFirst  bool
	aTS0    uint32
	aWall0  time.Time
	vFirst  bool
	vTS0    uint32
	vWall0  time.Time
	lastKey bool
}

type audioSample struct {
	data []byte
	ms   int64
}

type segment struct {
	f     *os.File
	audio webm.BlockWriteCloser
	video webm.BlockWriteCloser
	file  RecordingFile
}

// videoSink adapts a participant to the forwarder's writer.
type videoSink struct{ p *partRec }

func (v videoSink) WriteRTP(pkt *rtp.Packet) error { v.p.pushVideo(pkt); return nil }

func (p *partRec) msSince(wall0 time.Time, ts0, ts uint32, clock uint32) int64 {
	d := int64(int32(ts - ts0))
	return wall0.Sub(p.base).Milliseconds() + d*1000/int64(clock)
}

func (p *partRec) pushAudio(pkt *rtp.Packet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.asb == nil {
		p.asb = samplebuilder.New(10, &codecs.OpusPacket{}, 48000)
	}
	if !p.aFirst {
		p.aFirst, p.aTS0, p.aWall0 = true, pkt.Timestamp, time.Now()
		p.firstA = p.aWall0
	}
	cp := *pkt
	p.asb.Push(&cp)
	for {
		s := p.asb.Pop()
		if s == nil {
			return
		}
		ms := p.msSince(p.aWall0, p.aTS0, s.PacketTimestamp, 48000)
		if p.cur == nil {
			if len(p.pending) < 400 { // about eight seconds
				p.pending = append(p.pending, audioSample{append([]byte(nil), s.Data...), ms})
			}
			continue
		}
		if p.cur.audio != nil {
			_, _ = p.cur.audio.Write(true, ms, s.Data)
		}
	}
}

func (p *partRec) setVideo(kind codecKind, svc bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.vr == nil {
		p.vr = newVideoRec(kind, svc)
	}
}

func (p *partRec) pushVideo(pkt *rtp.Packet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.vr == nil {
		return
	}
	if !p.vFirst {
		p.vFirst, p.vTS0, p.vWall0 = true, pkt.Timestamp, time.Now()
	}
	for _, s := range p.vr.push(pkt) {
		ms := p.msSince(p.vWall0, p.vTS0, s.ts, 90000)
		if p.cur == nil || (p.cur.video == nil && s.key) {
			if !s.key {
				continue // a picture can only start on a keyframe
			}
			w, h := p.vr.dims(s)
			p.openLocked(true, w, h, s)
		}
		if p.cur != nil && p.cur.video != nil {
			_, _ = p.cur.video.Write(s.key, ms, p.vr.store(s))
		}
	}
}

// vp8Size reads the picture size from a keyframe.
func vp8Size(frame []byte) (int, int) {
	if len(frame) < 10 || frame[3] != 0x9d || frame[4] != 0x01 || frame[5] != 0x2a {
		return 640, 480
	}
	return int(uint16(frame[6])|uint16(frame[7])<<8) & 0x3fff, int(uint16(frame[8])|uint16(frame[9])<<8) & 0x3fff
}

// maybeStartAudioOnly opens a file without video for a participant who only
// sends audio (camera off), so their voice is not held in memory forever.
func (p *partRec) maybeStartAudioOnly(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.cur != nil || !p.aFirst || now.Sub(p.firstA) < audioOnlyAfter {
		return
	}
	p.openLocked(false, 0, 0, vsample{})
}

// openLocked starts a new file. If an audio-only file is open and video turns
// up, it is closed and a new file with both begins: WebM cannot add a track.
func (p *partRec) openLocked(withVideo bool, w, h int, first vsample) {
	if p.cur != nil {
		p.closeSegmentLocked()
	}
	p.seg++
	ext := "webm"
	if withVideo && p.vr != nil {
		ext = p.vr.ext()
	}
	name := fmt.Sprintf("%s-%d.%s", safeName(p.user), p.seg, ext)
	path := filepath.Join(p.rec.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	tracks := []webm.TrackEntry{}
	hasAudio := p.aFirst
	if hasAudio {
		tracks = append(tracks, webm.TrackEntry{Name: "Audio", TrackNumber: 1, TrackUID: 1, CodecID: "A_OPUS", TrackType: 2,
			DefaultDuration: 20_000_000, Audio: &webm.Audio{SamplingFrequency: 48000.0, Channels: 2}})
	}
	var opts []mkvcore.BlockWriterOption
	if withVideo && p.vr != nil {
		tracks = append(tracks, p.vr.track(w, h, first))
		opts = p.vr.options()
	}
	if len(tracks) == 0 {
		_ = f.Close()
		_ = os.Remove(path)
		return
	}
	ws, err := webm.NewSimpleBlockWriter(f, tracks, opts...)
	if err != nil {
		_ = f.Close()
		return
	}
	seg := &segment{f: f, file: RecordingFile{User: p.user, Path: path, StartedAt: time.Now().UTC(), Audio: hasAudio, Video: withVideo && p.vr != nil}}
	i := 0
	if hasAudio {
		seg.audio = ws[i]
		i++
	}
	if withVideo && p.vr != nil {
		seg.video = ws[i]
	}
	p.cur = seg
	for _, a := range p.pending { // the audio heard while waiting
		if seg.audio != nil {
			_, _ = seg.audio.Write(true, a.ms, a.data)
		}
	}
	p.pending = nil
}

func (p *partRec) closeSegmentLocked() {
	if p.cur == nil {
		return
	}
	if p.cur.audio != nil {
		_ = p.cur.audio.Close()
	}
	if p.cur.video != nil {
		_ = p.cur.video.Close()
	}
	p.done = append(p.done, p.cur.file)
	p.cur = nil
}

func (p *partRec) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.cur == nil && len(p.pending) > 0 {
		p.openLocked(false, 0, 0, vsample{})
	}
	p.closeSegmentLocked()
}

func (p *partRec) files() []RecordingFile {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append([]RecordingFile(nil), p.done...)
	if p.cur != nil {
		out = append(out, p.cur.file)
	}
	return out
}

// watchRecording ends a recording that has run too long, or that is filling
// the disk, so an unattended recording cannot take the machine down with it.
func (s *Server) watchRecording(r *room, rec *recording) {
	if s.cfg.RecordMaxDuration <= 0 && s.cfg.RecordMinFree == 0 {
		return
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
		case <-s.stop:
			return
		}
		if r.rec.Load() != rec {
			return // stopped by someone
		}
		over := s.cfg.RecordMaxDuration > 0 && time.Since(rec.info.StartedAt) >= s.cfg.RecordMaxDuration
		if !over && s.cfg.RecordMinFree > 0 {
			if free, ok := freeBytes(s.cfg.RecordDir); ok && free < s.cfg.RecordMinFree/2 {
				over = true
			}
		}
		if over {
			if r.rec.CompareAndSwap(rec, nil) {
				rec.finish()
				r.mu.Lock()
				users := make([]string, 0, len(r.peers))
				for u, p := range r.peers {
					if !p.relay {
						users = append(users, u)
					}
				}
				r.mu.Unlock()
				if n, ok := s.sig.(RecordingNotifier); ok {
					_ = n.Recording(r.id, false, "system", users)
				}
			}
			return
		}
	}
}

package sfu

import (
	"sort"
	"sync"
	"time"
)

// Room policy: how many people a room may hold and how many of them each
// viewer is sent at once.
//
// In a room of a hundred people, forwarding everyone to everyone is neither
// possible (a hundred video sections in every viewer's connection) nor useful
// (nobody watches a hundred tiles). A room with LastNVideo or LastNAudio set
// forwards, to each viewer, only the people who spoke most recently, plus
// whoever the viewer pinned. Everyone is still in the room and can still be
// heard when they speak: speaking brings a person into the set, and the person
// who has been quiet longest leaves it.

// Policy is a room's limits. A zero field takes the server's Config value.
type Policy struct {
	// MaxPeers is the most participants in the room.
	MaxPeers int `json:"max_peers,omitempty"`
	// LastNVideo is how many people's video each viewer is sent. 0 is everyone.
	LastNVideo int `json:"last_n_video,omitempty"`
	// LastNAudio is how many people's audio each viewer is sent. 0 is everyone.
	LastNAudio int `json:"last_n_audio,omitempty"`
}

func (p Policy) merge(base Policy) Policy {
	if p.MaxPeers <= 0 {
		p.MaxPeers = base.MaxPeers
	}
	if p.LastNVideo <= 0 {
		p.LastNVideo = base.LastNVideo
	}
	if p.LastNAudio <= 0 {
		p.LastNAudio = base.LastNAudio
	}
	return p
}

// policies remembers a room's policy from before its first participant joins.
type policies struct {
	mu sync.Mutex
	m  map[string]Policy
}

// SetPolicy sets the policy of a room. It may be called before anyone has
// joined, and again while the room is live: a change in what is forwarded is
// negotiated with every viewer.
func (s *Server) SetPolicy(roomID string, pol Policy) {
	s.pol.mu.Lock()
	if s.pol.m == nil {
		s.pol.m = map[string]Policy{}
	}
	s.pol.m[roomID] = pol
	s.pol.mu.Unlock()
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r != nil {
		r.pol.Store(&pol)
		r.reselect(time.Now(), true)
	}
}

// ForgetPolicy drops a room's remembered policy once the room is over.
func (s *Server) ForgetPolicy(roomID string) {
	s.pol.mu.Lock()
	delete(s.pol.m, roomID)
	s.pol.mu.Unlock()
}

func (s *Server) policyFor(roomID string) Policy {
	s.pol.mu.Lock()
	p := s.pol.m[roomID]
	s.pol.mu.Unlock()
	return p
}

// effective is the room's limits with the server's defaults filled in.
func (r *room) effective(cfg Config) Policy {
	base := Policy{MaxPeers: cfg.MaxPeers, LastNVideo: cfg.LastNVideo, LastNAudio: cfg.LastNAudio}
	if p := r.pol.Load(); p != nil {
		return p.merge(base)
	}
	return base
}

// selection is who a viewer is sent. A nil set means everyone.
type selection struct {
	video, audio map[string]bool
}

// reselect works out the last N speakers and, if that set changed, brings every
// viewer's connection in line with it. force renegotiates regardless.
func (r *room) reselect(now time.Time, force bool) {
	pol := r.effective(r.srv.cfg)
	if pol.LastNVideo <= 0 && pol.LastNAudio <= 0 {
		if r.sel.Swap(nil) != nil || force {
			r.renegotiateAll()
		}
		return
	}
	r.mu.Lock()
	type cand struct {
		user   string
		spoke  time.Time
		joined time.Time
	}
	cands := make([]cand, 0, len(r.peers))
	for u, p := range r.peers {
		if p.relay {
			continue
		}
		cands = append(cands, cand{u, r.spoke[u], p.joined})
	}
	r.mu.Unlock()
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		switch {
		case !a.spoke.Equal(b.spoke):
			return a.spoke.After(b.spoke)
		case !a.joined.Equal(b.joined):
			return a.joined.Before(b.joined)
		}
		return a.user < b.user
	})
	pick := func(n int) map[string]bool {
		if n <= 0 {
			return nil
		}
		out := make(map[string]bool, n)
		for i := 0; i < len(cands) && i < n; i++ {
			out[cands[i].user] = true
		}
		return out
	}
	next := &selection{video: pick(pol.LastNVideo), audio: pick(pol.LastNAudio)}
	if cur := speakerOf(r); cur != "" { // whoever is talking right now is always in
		if next.video != nil {
			next.video[cur] = true
		}
		if next.audio != nil {
			next.audio[cur] = true
		}
	}
	old := r.sel.Load()
	if !force && old != nil && sameSet(old.video, next.video) && sameSet(old.audio, next.audio) {
		return
	}
	r.sel.Store(next)
	r.renegotiateAll()
}

func speakerOf(r *room) string { return r.currentSpeaker() }

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// allows reports whether the selection sends viewer someone's track.
func (sel *selection) allows(viewer *peer, owner string, video bool) bool {
	if sel == nil || viewer.relay {
		return true
	}
	set := sel.audio
	if video {
		set = sel.video
	}
	if set == nil || set[owner] {
		return true
	}
	viewer.fmu.Lock()
	pinned := viewer.prefs.Pinned
	viewer.fmu.Unlock()
	return pinned != "" && pinned == owner
}

func (r *room) renegotiateAll() {
	r.mu.Lock()
	all := make([]*peer, 0, len(r.peers))
	for _, p := range r.peers {
		all = append(all, p)
	}
	r.mu.Unlock()
	for _, p := range all {
		p.scheduleRenegotiate()
	}
}

// scheduleRenegotiate asks for p's connection to be brought in line with the
// room, soon. Many changes close together (a hundred people arriving) become
// one offer each instead of one offer per change: the wait grows with the size
// of the room, and is none in a small one.
func (p *peer) scheduleRenegotiate() {
	n := p.room.size()
	if n <= smallRoom {
		go p.renegotiate()
		return
	}
	if !p.scheduled.CompareAndSwap(false, true) {
		return
	}
	d := time.Duration(n-smallRoom) * 8 * time.Millisecond
	if d > 800*time.Millisecond {
		d = 800 * time.Millisecond
	}
	time.AfterFunc(d, func() {
		p.scheduled.Store(false)
		p.renegotiate()
	})
}

// smallRoom is the size up to which changes are negotiated at once.
const smallRoom = 16

func (r *room) size() int {
	r.mu.Lock()
	n := len(r.peers)
	r.mu.Unlock()
	return n
}

// newRoom makes an empty room, with the policy its backend set for it, if any.
// The caller holds s.mu and adds it to s.rooms.
func (s *Server) newRoom(id string) *room {
	r := &room{id: id, srv: s, peers: map[string]*peer{}, pubs: map[string]*published{}, spoke: map[string]time.Time{}, det: newSpeakerDetector()}
	if pol := s.policyFor(id); pol != (Policy{}) {
		r.pol.Store(&pol)
	}
	return r
}

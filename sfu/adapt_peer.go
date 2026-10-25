package sfu

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

// Prefs is what a subscriber tells the server about how it wants video.
type Prefs struct {
	// Streams maps a publisher's user id to the subscriber's wishes for them.
	Streams map[string]StreamPref `json:"streams,omitempty"`
	// Pinned names a publisher to favour when bandwidth is short (the speaker
	// shown large).
	Pinned string `json:"pinned,omitempty"`
	// MaxKbps caps the subscriber's video bandwidth: a data-saver setting.
	// Zero means no cap.
	MaxKbps int `json:"max_kbps,omitempty"`
}

// StreamPref is a subscriber's wish for one publisher's video.
type StreamPref struct {
	// Max is the largest layer worth sending: the tile is small, so "q" will do.
	Max string `json:"max,omitempty"`
	// Paused stops the video while the tile is hidden (scrolled away, a closed
	// tab). It is the only way someone's video is withheld.
	Paused bool `json:"paused,omitempty"`
}

var ridPattern = regexp.MustCompile(`^[a-z0-9]{0,8}$`)

// Prefer replaces a participant's video preferences.
func (s *Server) Prefer(roomID, user string, pr Prefs) error {
	p := s.find(roomID, user)
	if p == nil {
		return ErrNoPeer
	}
	if len(pr.Streams) > 200 || len(pr.Pinned) > 200 || pr.MaxKbps < 0 || pr.MaxKbps > 100_000 {
		return ErrBadPrefs
	}
	clean := Prefs{Streams: make(map[string]StreamPref, len(pr.Streams)), Pinned: pr.Pinned, MaxKbps: pr.MaxKbps}
	for who, sp := range pr.Streams {
		if len(who) > 200 || !ridPattern.MatchString(sp.Max) {
			return ErrBadPrefs
		}
		clean.Streams[who] = sp
	}
	p.fmu.Lock()
	pinChanged := p.prefs.Pinned != clean.Pinned
	p.prefs = clean
	p.fmu.Unlock()
	if pinChanged && p.room.sel.Load() != nil {
		p.scheduleRenegotiate() // a pinned person is sent even outside the last N
	}
	go p.adapt(time.Now())
	return nil
}

// LayerStat describes one layer of someone's video.
type LayerStat struct {
	RID    string `json:"rid"`
	Kbps   int    `json:"kbps"`
	Active bool   `json:"active"`
}

// StreamStat is what one participant receives from one publisher.
type StreamStat struct {
	Publisher string      `json:"publisher"`
	Layer     string      `json:"layer"`  // being forwarded now
	Target    string      `json:"target"` // being moved to
	Paused    bool        `json:"paused"`
	Switches  int         `json:"switches"`
	Kbps      int         `json:"kbps"` // of the layer in use
	Layers    []LayerStat `json:"layers"`
}

// PeerStats is a participant's downstream, for display and diagnosis.
type PeerStats struct {
	// EstimateKbps is the estimated capacity of the participant's link; zero
	// when unknown. BudgetKbps is what video may use of it (-1: unlimited).
	EstimateKbps int    `json:"estimate_kbps"`
	BudgetKbps   int    `json:"budget_kbps"`
	UsageKbps    int    `json:"usage_kbps"`
	State        string `json:"state"`
	Recording    bool   `json:"recording"` // the room is being recorded
	E2EE         bool   `json:"e2ee"`      // the room is end-to-end encrypted
	// Notes are things the participant should be told about their own stream.
	Notes   []string     `json:"notes"`
	Speaker string       `json:"speaker"` // who is talking in the room now
	Streams []StreamStat `json:"streams"`
	// Unavailable lists people whose video this participant cannot be sent, and
	// why; they are still heard.
	Unavailable []Unavailable `json:"unavailable"`
}

// Unavailable names a video that cannot be delivered to a participant.
type Unavailable struct {
	Publisher string `json:"publisher"`
	Reason    string `json:"reason"`
}

// PeerStats reports a participant's current downstream.
func (s *Server) PeerStats(roomID, user string) (PeerStats, error) {
	p := s.find(roomID, user)
	if p == nil {
		return PeerStats{}, ErrNoPeer
	}
	p.adapt(time.Now())
	p.fmu.Lock()
	defer p.fmu.Unlock()
	out := p.last
	out.Streams = append([]StreamStat{}, p.last.Streams...) // never nil: clients map over it
	out.Unavailable = append([]Unavailable{}, p.last.Unavailable...)
	out.Notes = append([]string{}, p.last.Notes...)
	return out, nil
}

// estimateKbps is the subscriber's estimated link capacity, 0 if unknown.
func (p *peer) estimateKbps() int {
	if f := p.srv.cfg.estimate; f != nil {
		if v, ok := f(p.room.id, p.user); ok {
			return v
		}
	}
	if p.est == nil {
		return 0
	}
	// An estimator fed no feedback (a client that did not negotiate transport-
	// wide congestion control) never moves off its starting guess; after a few
	// seconds that guess is noise, not a measurement.
	if !p.estSeen.Load() && time.Since(p.joined) > 6*time.Second {
		return 0
	}
	return p.est.GetTargetBitrate() / 1000
}

const audioKbps = 40

// adapt chooses the layer of each video this participant receives.
func (p *peer) adapt(now time.Time) {
	if p.relay {
		return // a relay is sent every layer; there is nothing to choose
	}
	p.fmu.Lock()
	entries := make(map[string]*subEntry, len(p.fwds))
	for id, e := range p.fwds {
		entries[id] = e
	}
	prefs := p.prefs
	p.fmu.Unlock()

	streams := make([]streamIn, 0, len(entries))
	for id, e := range entries {
		owner := e.pub.who
		sp := prefs.Streams[owner]
		pri := 0
		switch {
		case prefs.Pinned != "" && prefs.Pinned == owner:
			pri = 100 // what the viewer chose to look at
		case owner == p.room.currentSpeaker():
			pri = 50 // whoever is talking is raised before the rest
		}
		streams = append(streams, streamIn{ID: id, Layers: e.pub.layerInfos(now), Max: sp.Max, Hidden: sp.Paused, Priority: pri})
	}
	sort.Slice(streams, func(i, j int) bool { return streams[i].ID < streams[j].ID })

	estimate := p.estimateKbps()
	budget := budgetKbps(estimate, prefs.MaxKbps, int(p.audioN.Load())*audioKbps)

	p.fmu.Lock()
	choice := p.ad.step(now, streams, budget, estimate)
	p.fmu.Unlock()

	stats := PeerStats{EstimateKbps: estimate, BudgetKbps: budget, State: p.pc.ConnectionState().String(), Speaker: p.room.currentSpeaker(), Recording: p.room.rec.Load() != nil, E2EE: p.room.e2ee.Load(), Notes: []string{}, Streams: []StreamStat{}, Unavailable: []Unavailable{}}
	if budget >= unlimited {
		stats.BudgetKbps = -1
	}
	for _, s := range streams {
		e := entries[s.ID]
		rid := choice[s.ID]
		e.fwd.setPaused(s.Hidden)
		e.fwd.setTarget(rid)
		st := e.fwd.state()
		ss := StreamStat{Publisher: e.pub.who, Layer: st.Cur, Target: rid, Paused: s.Hidden, Switches: st.Switches}
		for _, l := range s.Layers {
			ss.Layers = append(ss.Layers, LayerStat{RID: l.RID, Kbps: l.Kbps, Active: l.Active})
			if l.RID == st.Cur {
				ss.Kbps = l.cost()
			}
		}
		if !s.Hidden {
			stats.UsageKbps += ss.Kbps
		}
		stats.Streams = append(stats.Streams, ss)
	}
	sort.Slice(stats.Streams, func(i, j int) bool { return stats.Streams[i].Publisher < stats.Streams[j].Publisher })
	p.fmu.Lock()
	for id, why := range p.unavailable {
		who := id
		if i := strings.IndexByte(id, ':'); i > 0 {
			who = id[:i]
		}
		stats.Unavailable = append(stats.Unavailable, Unavailable{Publisher: who, Reason: why})
	}
	sort.Slice(stats.Unavailable, func(i, j int) bool { return stats.Unavailable[i].Publisher < stats.Unavailable[j].Publisher })
	stats.Notes = append(stats.Notes, p.notes...)
	p.last = stats
	p.fmu.Unlock()
}

// ---------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------

func (s *Server) housekeeping() {
	defer s.wg.Done()
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	tick := 0
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		tick++
		now := time.Now()
		var peers []*peer
		var pubs []*published
		var rooms []*room
		s.mu.Lock()
		for _, r := range s.rooms {
			rooms = append(rooms, r)
			r.mu.Lock()
			for _, p := range r.peers {
				peers = append(peers, p)
			}
			for _, pub := range r.pubs {
				pubs = append(pubs, pub)
			}
			r.mu.Unlock()
		}
		s.mu.Unlock()
		if tick%4 == 0 {
			for _, pub := range pubs {
				pub.measure()
			}
		}
		for _, r := range rooms {
			s.detectSpeaker(r, now)
			if rec := r.rec.Load(); rec != nil {
				rec.tick(now, s.cfg.RecordLayer == "lowest")
			}
		}
		for _, p := range peers {
			if tick%2 == 0 {
				p.adapt(now)
			}
			p.checkOffer(now)
		}
	}
}

// measure updates each layer's bitrate from the bytes seen in the last second.
func (p *published) measure() {
	p.lmu.RLock()
	defer p.lmu.RUnlock()
	for _, l := range p.layers {
		total := l.bytes.Load()
		inst := int64(total-l.prev) * 8 / 1000
		l.prev = total
		if old := l.kbps.Load(); old > 0 {
			inst = (old + inst) / 2
		}
		l.kbps.Store(inst)
	}
}

// checkOffer repairs a server offer that was never answered: the signaling
// channel may have dropped it (a network switch is exactly when that happens).
// The same offer is sent again, with growing gaps, until it is answered; the
// answer to a stale offer is harmless, because anything that changed since is
// picked up by the renegotiation that follows. (A rollback is not an option:
// Pion's public API does not offer one.) Only a long silence, far past the
// reconnect grace, ends the participant: they are gone and will rejoin.
func (p *peer) checkOffer(now time.Time) {
	p.nmu.Lock()
	if p.closing || p.offer == nil {
		p.nmu.Unlock()
		return
	}
	cfg := p.srv.cfg
	if now.Sub(p.offer.first) > 4*cfg.ReconnectGrace+cfg.OfferTimeout {
		p.nmu.Unlock()
		p.close()
		return
	}
	wait := cfg.OfferTimeout << min(p.offer.tries-1, 3)
	if now.Sub(p.offer.at) < wait {
		p.nmu.Unlock()
		return
	}
	p.offer.tries++
	p.offer.at = now
	sdp := p.offer.sdp
	p.nmu.Unlock()
	_ = p.sendOffer(sdp)
}

// detectSpeaker looks at how loud each participant has been since the last look
// and, if the dominant speaker changed, says so.
func (s *Server) detectSpeaker(r *room, now time.Time) {
	r.mu.Lock()
	loud := make(map[string]int, len(r.peers))
	users := make([]string, 0, len(r.peers))
	for u, p := range r.peers {
		if p.relay {
			continue // a relay is not a person (the speaker is detected on each node's own microphones)
		}
		loud[u] = p.meter.take()
		users = append(users, u)
	}
	r.mu.Unlock()
	r.noteSpeech(now, loud)
	cur, changed := r.det.update(now, loud)
	if !changed {
		return
	}
	r.speaker.Store(cur)
	r.reselect(now, false)
	if n, ok := s.sig.(SpeakerNotifier); ok {
		_ = n.Speaker(r.id, cur, users)
	}
}

// noteSpeech remembers who has been talking, for the last-N selection.
func (r *room) noteSpeech(now time.Time, loud map[string]int) {
	r.mu.Lock()
	for u, l := range loud {
		if l >= speechLoudness {
			r.spoke[u] = now
		}
	}
	for u := range r.spoke {
		if _, here := loud[u]; !here {
			delete(r.spoke, u)
		}
	}
	r.mu.Unlock()
}

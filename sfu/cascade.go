package sfu

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// Cascading: one room across several nodes.
//
// A room has a home node (the hub). A node whose participants join a room homed
// elsewhere is a leaf: it keeps a relay link to the hub and serves its own
// participants locally. Each publisher's video crosses the link once, with all of
// its layers, however many people watch it on the other side; every node then
// adapts each local viewer on its own, exactly as it does for a single-node room.
//
// A link is two one-way connections, because Pion has no rollback and two sides
// that may both renegotiate one connection can deadlock on colliding offers:
//
//	up    leaf -> hub   the leaf is the offerer; it carries the leaf's participants
//	down  hub -> leaf   the hub is the offerer; it carries everyone else
//
// Whoever offers on a connection is the only one that ever does. The hub sees
// each as a participant named "relay:<node>:up" / "relay:<node>:down", and a
// relayed track keeps its original publisher's name (its stream id), so nothing
// downstream can tell a relayed person from a local one.
//
// Star topology only: leaves do not relay for other leaves.

// RelayLink carries a hub's messages to a leaf.
type RelayLink interface {
	Offer(webrtc.SessionDescription) error
	Candidate(webrtc.ICECandidateInit) error
}

// Upstream is what a leaf calls on its hub. which is "up" or "down".
type Upstream interface {
	Join(ctx context.Context, which string, offer webrtc.SessionDescription, back RelayLink) (webrtc.SessionDescription, error)
	Answer(which string, answer webrtc.SessionDescription) error
	Candidate(which string, c webrtc.ICECandidateInit) error
	Ready(which string) error
	Restart(ctx context.Context, which string, offer webrtc.SessionDescription) (webrtc.SessionDescription, error)
	Leave() error
}

type relayJoin struct {
	node string
	up   bool
	back RelayLink
}

// RelayUser is the name under which a leaf's connection appears in the hub's room.
func RelayUser(node, which string) string { return "relay:" + node + ":" + which }

// JoinRelay is the hub's side of Upstream.Join.
func (s *Server) JoinRelay(ctx context.Context, roomID, node, which string, offer webrtc.SessionDescription, back RelayLink) (webrtc.SessionDescription, error) {
	return s.joinRelay(ctx, roomID, node, which, offer, back, false)
}

// JoinRelaySecure is JoinRelay for a room whose media is end-to-end encrypted:
// it marks the hub's room as encrypted even if the relay arrives before any
// local participant, so a plain join cannot slip in behind it.
func (s *Server) JoinRelaySecure(ctx context.Context, roomID, node, which string, offer webrtc.SessionDescription, back RelayLink) (webrtc.SessionDescription, error) {
	return s.joinRelay(ctx, roomID, node, which, offer, back, true)
}

func (s *Server) joinRelay(ctx context.Context, roomID, node, which string, offer webrtc.SessionDescription, back RelayLink, secure bool) (webrtc.SessionDescription, error) {
	if which != "up" && which != "down" {
		return webrtc.SessionDescription{}, errors.New("sfu: a relay is up or down")
	}
	return s.join(ctx, roomID, RelayUser(node, which), offer, &relayJoin{node: node, up: which == "up", back: back}, secure)
}

// LocalUpstream connects a leaf to a hub in the same process (tests, and a
// single binary running several nodes).
type LocalUpstream struct {
	Hub  *Server
	Room string
	Node string
	// Secure marks the room as end-to-end encrypted on the hub.
	Secure bool
}

func (l LocalUpstream) Join(ctx context.Context, which string, offer webrtc.SessionDescription, back RelayLink) (webrtc.SessionDescription, error) {
	if l.Secure {
		return l.Hub.JoinRelaySecure(ctx, l.Room, l.Node, which, offer, back)
	}
	return l.Hub.JoinRelay(ctx, l.Room, l.Node, which, offer, back)
}
func (l LocalUpstream) Answer(which string, a webrtc.SessionDescription) error {
	return l.Hub.Answer(l.Room, RelayUser(l.Node, which), a)
}
func (l LocalUpstream) Candidate(which string, c webrtc.ICECandidateInit) error {
	return l.Hub.Candidate(l.Room, RelayUser(l.Node, which), c)
}
func (l LocalUpstream) Ready(which string) error {
	return l.Hub.Ready(l.Room, RelayUser(l.Node, which))
}
func (l LocalUpstream) Restart(ctx context.Context, which string, o webrtc.SessionDescription) (webrtc.SessionDescription, error) {
	return l.Hub.Restart(ctx, l.Room, RelayUser(l.Node, which), o)
}
func (l LocalUpstream) Leave() error {
	l.Hub.Leave(l.Room, RelayUser(l.Node, "up"))
	l.Hub.Leave(l.Room, RelayUser(l.Node, "down"))
	return nil
}

// ---------------------------------------------------------------------------
// layeredOut: a video sent whole to another node
// ---------------------------------------------------------------------------

// relayRIDs are always offered for a simulcast video: the layers may start a
// moment apart, and the section cannot gain a layer after it is negotiated.
var relayRIDs = []string{"q", "h", "f"}

type layerExt struct {
	midID, ridID uint8
	mid          string
}

// layeredOut sends one published video to another node untouched: each simulcast
// layer as its own stream (the other node needs them all to serve its own viewers
// at their own qualities), or the single stream of a non-simulcast / SVC video.
type layeredOut struct {
	pub    *published
	tr     *webrtc.RTPTransceiver
	sender *webrtc.RTPSender
	tracks map[string]*webrtc.TrackLocalStaticRTP // by rid; "" for a single stream
	multi  bool
	ext    atomic.Pointer[layerExt]
}

func newLayeredOut(pc *webrtc.PeerConnection, pub *published, id string) (*layeredOut, error) {
	o := &layeredOut{pub: pub, tracks: map[string]*webrtc.TrackLocalStaticRTP{}, multi: pub.rids}
	if !o.multi {
		t, err := webrtc.NewTrackLocalStaticRTP(pub.codec, id, pub.who)
		if err != nil {
			return nil, err
		}
		tr, err := pc.AddTransceiverFromTrack(t, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
		if err != nil {
			return nil, err
		}
		o.tracks[""], o.tr, o.sender = t, tr, tr.Sender()
		return o, nil
	}
	rids := append([]string(nil), relayRIDs...)
	pub.lmu.RLock()
	for rid := range pub.layers {
		found := false
		for _, r := range rids {
			found = found || r == rid
		}
		if !found {
			rids = append(rids, rid)
		}
	}
	pub.lmu.RUnlock()
	sort.SliceStable(rids, func(i, j int) bool { return rankOf(rids[i]) < rankOf(rids[j]) })
	for i, rid := range rids {
		t, err := webrtc.NewTrackLocalStaticRTP(pub.codec, id, pub.who, webrtc.WithRTPStreamID(rid))
		if err != nil {
			return nil, err
		}
		if i == 0 {
			tr, err := pc.AddTransceiverFromTrack(t, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
			if err != nil {
				return nil, err
			}
			o.tr, o.sender = tr, tr.Sender()
		} else if err := o.sender.AddEncoding(t); err != nil {
			return nil, err
		}
		o.tracks[rid] = t
	}
	return o, nil
}

// start reads the other node's feedback: its request for a keyframe becomes a
// request to the publisher, for the layer that asked.
func (o *layeredOut) start() {
	if o.multi {
		for rid := range o.tracks {
			rid := rid
			go func() {
				for {
					pkts, _, err := o.sender.ReadSimulcastRTCP(rid)
					if err != nil {
						return
					}
					for _, p := range pkts {
						switch p.(type) {
						case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
							o.pub.askKeyframe(rid)
						}
					}
				}
			}()
		}
	} else {
		go readRTCP(o.sender, o)
	}
	o.keyframeWanted() // the other side starts with nothing decoded
}

func (o *layeredOut) extension() *layerExt {
	if e := o.ext.Load(); e != nil {
		return e
	}
	var e layerExt
	for _, he := range o.sender.GetParameters().HeaderExtensions {
		switch he.URI {
		case "urn:ietf:params:rtp-hdrext:sdes:mid":
			e.midID = uint8(he.ID)
		case "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id":
			e.ridID = uint8(he.ID)
		}
	}
	e.mid = o.tr.Mid()
	if e.midID == 0 || e.ridID == 0 || e.mid == "" {
		return nil // not negotiated yet
	}
	o.ext.Store(&e)
	return &e
}

func (o *layeredOut) push(rid string, pkt *rtp.Packet) {
	t := o.tracks[rid]
	if !o.multi {
		t = o.tracks[""]
	}
	if t == nil {
		return
	}
	out := &rtp.Packet{Header: pkt.Header, Payload: pkt.Payload}
	out.Header.Extension, out.Header.Extensions = false, nil
	if o.multi {
		e := o.extension()
		if e == nil {
			return
		}
		_ = out.Header.SetExtension(e.midID, []byte(e.mid))
		_ = out.Header.SetExtension(e.ridID, []byte(rid))
	}
	_ = t.WriteRTP(out)
}

func (o *layeredOut) setTarget(string)  {}
func (o *layeredOut) setPaused(bool)    {}
func (o *layeredOut) state() layerState { return layerState{} }
func (o *layeredOut) keyframeWanted() {
	o.pub.lmu.RLock()
	rids := make([]string, 0, len(o.pub.layers))
	for rid := range o.pub.layers {
		rids = append(rids, rid)
	}
	o.pub.lmu.RUnlock()
	for _, rid := range rids {
		o.pub.askKeyframe(rid)
	}
}

// expectKeyframe: a relay sends what it gets untouched, so the node on the other
// side is the one that watches for damage; here it is enough to ask the publisher.
func (o *layeredOut) expectKeyframe() { o.keyframeWanted() }

var _ layerSink = (*layeredOut)(nil)

// ---------------------------------------------------------------------------
// Cascade: the leaf's side
// ---------------------------------------------------------------------------

var errBusy = errors.New("sfu: the relay connection is negotiating")

// Cascade is a leaf's relay link to a room's hub.
type Cascade struct {
	s    *Server
	r    *room
	node string // the hub's name, for naming
	self string // this leaf's name, as the hub knows it
	up   Upstream

	mu      sync.Mutex
	closed  bool
	syncing bool
	dirty   bool

	upPC    *webrtc.PeerConnection
	rpUp    *peer
	outs    map[string]*layeredOut
	audio   map[string]*audioOut
	upOK    bool
	upQueue []webrtc.ICECandidateInit
	// The hub's candidates are held until the answer to our offer is applied; a
	// candidate for a connection with no remote description cannot be added.
	upRemote, downRemote bool
	hubUpQ, hubDownQ     []webrtc.ICECandidateInit

	downPC    *webrtc.PeerConnection
	rpDown    *peer
	downOK    bool
	downQueue []webrtc.ICECandidateInit
	dmu       sync.Mutex // serializes work on the down connection
}

// OpenCascade makes this node a leaf of roomID's hub. It is idempotent.
func (s *Server) OpenCascade(ctx context.Context, roomID, self string, up Upstream) (*Cascade, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	r := s.rooms[roomID]
	if r == nil {
		if len(s.rooms) >= s.cfg.MaxRooms {
			s.mu.Unlock()
			return nil, ErrRoomFull
		}
		r = &room{id: roomID, peers: map[string]*peer{}, pubs: map[string]*published{}, det: newSpeakerDetector()}
		s.rooms[roomID] = r
	}
	s.mu.Unlock()
	r.mu.Lock()
	if r.cascade != nil {
		c := r.cascade
		r.mu.Unlock()
		return c, nil
	}
	c := &Cascade{s: s, r: r, self: self, node: "hub", up: up, outs: map[string]*layeredOut{}, audio: map[string]*audioOut{}}
	r.cascade = c
	r.mu.Unlock()
	if err := c.openDown(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("sfu: cascade down: %w", err)
	}
	if err := c.openUp(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("sfu: cascade up: %w", err)
	}
	go c.sync()
	return c, nil
}

// Cascade returns a room's relay link, if it has one.
func (s *Server) Cascade(roomID string) *Cascade {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cascade
}

// newRelayPeer is the leaf's own peer for one of its relay connections.
func (c *Cascade) newRelayPeer(which string, pc *webrtc.PeerConnection) *peer {
	return &peer{
		user: RelayUser(c.self, which), room: c.r, pc: pc, srv: c.s, joined: time.Now(),
		relay: true, relayNode: c.self, noOffer: which == "down", ready: true,
		senders: map[string]*webrtc.RTPSender{}, trans: map[string]*webrtc.RTPTransceiver{}, fwds: map[string]*subEntry{},
		unavailable: map[string]string{}, ad: newAdapter(defaultAdaptCfg()), prefs: Prefs{Streams: map[string]StreamPref{}}, done: make(chan struct{}),
	}
}

// dirLink delivers the hub's messages for one of the two connections.
type dirLink struct {
	c    *Cascade
	down bool
}

func (l dirLink) Offer(sd webrtc.SessionDescription) error {
	if !l.down {
		return errors.New("sfu: the up connection is never offered to")
	}
	return l.c.handleOffer(sd)
}

func (l dirLink) Candidate(ci webrtc.ICECandidateInit) error {
	c := l.c
	c.mu.Lock()
	var pc *webrtc.PeerConnection
	if l.down {
		if !c.downRemote {
			c.hubDownQ = append(c.hubDownQ, ci)
			c.mu.Unlock()
			return nil
		}
		pc = c.downPC
	} else {
		if !c.upRemote {
			c.hubUpQ = append(c.hubUpQ, ci)
			c.mu.Unlock()
			return nil
		}
		pc = c.upPC
	}
	c.mu.Unlock()
	if pc == nil {
		return nil
	}
	return pc.AddICECandidate(ci)
}

// openDown creates (or recreates) the connection that brings the hub's media in.
func (c *Cascade) openDown(ctx context.Context) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	return c.openDownLocked(ctx)
}

func (c *Cascade) openDownLocked(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	old, oldRP := c.downPC, c.rpDown
	c.downOK, c.downQueue = false, nil
	c.downRemote, c.hubDownQ = false, nil
	c.mu.Unlock()
	if oldRP != nil {
		oldRP.close() // its received videos leave the room; viewers' tiles go and come back
	} else if old != nil {
		_ = old.Close()
	}
	pc, _, err := c.s.newPC()
	if err != nil {
		return err
	}
	rp := c.newRelayPeer("down", pc)
	pc.OnTrack(func(remote *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) { rp.onTrack(remote, receiver) })
	pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
		if ci == nil {
			return
		}
		c.mu.Lock()
		if !c.downOK {
			c.downQueue = append(c.downQueue, ci.ToJSON())
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		_ = c.up.Candidate("down", ci.ToJSON())
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			go c.downLost(pc)
		}
	})
	// The hub sends us everything in its offers; this first offer only brings the
	// connection up.
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		_ = pc.Close()
		return err
	}
	offer, err := pc.CreateOffer(nil)
	if err == nil {
		err = pc.SetLocalDescription(offer)
	}
	if err != nil {
		_ = pc.Close()
		return err
	}
	answer, err := c.up.Join(ctx, "down", *pc.LocalDescription(), dirLink{c, true})
	if err != nil {
		_ = pc.Close()
		return err
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		_ = pc.Close()
		return err
	}
	c.mu.Lock()
	c.downPC, c.rpDown, c.downOK, c.downRemote = pc, rp, true, true
	queued, fromHub := c.downQueue, c.hubDownQ
	c.downQueue, c.hubDownQ = nil, nil
	c.mu.Unlock()
	c.r.mu.Lock()
	c.r.peers[rp.user] = rp
	c.r.mu.Unlock()
	for _, ci := range fromHub {
		_ = pc.AddICECandidate(ci)
	}
	_ = c.up.Ready("down")
	for _, ci := range queued {
		_ = c.up.Candidate("down", ci)
	}
	return nil
}

// downLost reopens the down connection. A failed connection cannot be repaired
// with an ICE restart here: the hub may have an offer outstanding on it and,
// without rollback, neither side could then proceed. A fresh connection can.
func (c *Cascade) downLost(pc *webrtc.PeerConnection) {
	c.mu.Lock()
	stale := c.closed || c.downPC != pc
	c.mu.Unlock()
	if stale {
		return
	}
	for attempt := 0; attempt < 8; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.openDown(ctx)
		cancel()
		if err == nil || errors.Is(err, ErrClosed) {
			return
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
}

// handleOffer answers an offer from the hub on the down connection. If this side
// is somehow mid-negotiation it declines, and the hub sends the offer again.
func (c *Cascade) handleOffer(sd webrtc.SessionDescription) error {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	c.mu.Lock()
	pc, ok := c.downPC, c.downOK
	c.mu.Unlock()
	if pc == nil || !ok {
		return errBusy
	}
	if pc.SignalingState() != webrtc.SignalingStateStable {
		return errBusy
	}
	if err := pc.SetRemoteDescription(sd); err != nil {
		return err
	}
	answer, err := pc.CreateAnswer(nil)
	if err == nil {
		err = pc.SetLocalDescription(answer)
	}
	if err != nil {
		return err
	}
	return c.up.Answer("down", *pc.LocalDescription())
}

// openUp creates (or recreates) the connection that carries this node's people.
func (c *Cascade) openUp(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	oldRP, oldOuts := c.rpUp, c.outs
	c.outs = map[string]*layeredOut{}
	c.upOK, c.upQueue = false, nil
	c.upRemote, c.hubUpQ = false, nil
	c.mu.Unlock()
	for id, o := range oldOuts {
		_ = id
		o.pub.removeSub(o)
	}
	if oldRP != nil {
		oldRP.close()
	}
	pc, _, err := c.s.newPC()
	if err != nil {
		return err
	}
	rp := c.newRelayPeer("up", pc)
	rp.cascade = c
	pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
		if ci == nil {
			return
		}
		c.mu.Lock()
		if !c.upOK {
			c.upQueue = append(c.upQueue, ci.ToJSON())
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		_ = c.up.Candidate("up", ci.ToJSON())
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			go c.upLost(pc)
		}
	})
	c.mu.Lock()
	c.upPC, c.rpUp = pc, rp
	c.mu.Unlock()
	made := c.addOuts(pc)
	if made == 0 { // an offer needs a section to carry ICE credentials
		if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly}); err != nil {
			_ = pc.Close()
			return err
		}
	}
	offer, err := pc.CreateOffer(nil)
	if err == nil {
		err = pc.SetLocalDescription(offer)
	}
	if err != nil {
		_ = pc.Close()
		return err
	}
	answer, err := c.up.Join(ctx, "up", *pc.LocalDescription(), dirLink{c, false})
	if err != nil {
		_ = pc.Close()
		return err
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		_ = pc.Close()
		return err
	}
	c.mu.Lock()
	c.upOK, c.upRemote = true, true
	queued, fromHub := c.upQueue, c.hubUpQ
	c.upQueue, c.hubUpQ = nil, nil
	c.mu.Unlock()
	c.r.mu.Lock()
	c.r.peers[rp.user] = rp
	c.r.mu.Unlock()
	for _, ci := range fromHub {
		_ = pc.AddICECandidate(ci)
	}
	_ = c.up.Ready("up")
	for _, ci := range queued {
		_ = c.up.Candidate("up", ci)
	}
	return nil
}

// upLost tries an ICE restart (the leaf is the only offerer on this connection,
// so that is safe) and rebuilds the connection if it cannot.
func (c *Cascade) upLost(pc *webrtc.PeerConnection) {
	c.mu.Lock()
	stale := c.closed || c.upPC != pc
	c.mu.Unlock()
	if stale {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if pc.ConnectionState() != webrtc.PeerConnectionStateClosed && pc.SignalingState() == webrtc.SignalingStateStable {
		if offer, err := pc.CreateOffer(&webrtc.OfferOptions{ICERestart: true}); err == nil && pc.SetLocalDescription(offer) == nil {
			if answer, err := c.up.Restart(ctx, "up", *pc.LocalDescription()); err == nil && pc.SetRemoteDescription(answer) == nil {
				return
			}
		}
	}
	for attempt := 0; attempt < 8; attempt++ {
		c2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.openUp(c2)
		cancel2()
		if err == nil || errors.Is(err, ErrClosed) {
			go c.sync()
			return
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
}

// addOuts gives every local video a sender on the up connection, returning how
// many sections it made.
func (c *Cascade) addOuts(pc *webrtc.PeerConnection) int {
	made := 0
	for id, pub := range c.localPubs() {
		c.mu.Lock()
		_, have := c.outs[id]
		c.mu.Unlock()
		if have {
			continue
		}
		var out *layeredOut
		var err error
		if pub.kind == webrtc.RTPCodecTypeVideo {
			out, err = newLayeredOut(pc, pub, id)
		}
		if pub.kind == webrtc.RTPCodecTypeAudio {
			err = c.addAudio(pc, pub, id)
			if err == nil {
				made++
			}
			continue
		}
		if err != nil || out == nil {
			continue
		}
		c.mu.Lock()
		c.outs[id] = out
		c.mu.Unlock()
		pub.addSub(out)
		out.start()
		made++
	}
	return made
}

// localPubs are the videos and audios published by people on this node.
func (c *Cascade) localPubs() map[string]*published {
	c.r.mu.Lock()
	defer c.r.mu.Unlock()
	out := make(map[string]*published, len(c.r.pubs))
	for id, pub := range c.r.pubs {
		if !pub.owner.relay {
			out[id] = pub
		}
	}
	return out
}

func (c *Cascade) addAudio(pc *webrtc.PeerConnection, pub *published, id string) error {
	t, err := webrtc.NewTrackLocalStaticRTP(pub.codec, id, pub.who)
	if err != nil {
		return err
	}
	tr, err := pc.AddTransceiverFromTrack(t, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	if err != nil {
		return err
	}
	go readRTCP(tr.Sender(), nil)
	tp := pub.addTap(func(pkt *rtp.Packet) {
		out := &rtp.Packet{Header: pkt.Header, Payload: pkt.Payload}
		out.Header.Extension, out.Header.Extensions = false, nil
		_ = t.WriteRTP(out)
	})
	c.mu.Lock()
	c.audio[id] = &audioOut{pub: pub, tap: tp, sender: tr.Sender()}
	c.mu.Unlock()
	return nil
}

type audioOut struct {
	pub    *published
	tap    *tap
	sender *webrtc.RTPSender
}

// sync brings the up connection in line with the people on this node: a sender
// for each of their tracks, and none for tracks that have gone. Only the leaf
// ever offers on it, so there is nothing to collide with.
func (c *Cascade) sync() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if c.syncing {
		c.dirty = true
		c.mu.Unlock()
		return
	}
	c.syncing = true
	c.mu.Unlock()
	for {
		c.syncOnce()
		c.mu.Lock()
		if !c.dirty || c.closed {
			c.syncing = false
			c.mu.Unlock()
			return
		}
		c.dirty = false
		c.mu.Unlock()
	}
}

func (c *Cascade) syncOnce() {
	c.mu.Lock()
	pc, ok := c.upPC, c.upOK
	c.mu.Unlock()
	if pc == nil || !ok || pc.SignalingState() != webrtc.SignalingStateStable {
		c.mu.Lock()
		c.dirty = true
		c.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		return
	}
	want := c.localPubs()
	changed := false
	c.mu.Lock()
	for id, o := range c.outs {
		if want[id] == nil {
			_ = pc.RemoveTrack(o.sender)
			o.pub.removeSub(o)
			delete(c.outs, id)
			changed = true
		}
	}
	for id, a := range c.audio {
		if want[id] == nil {
			_ = pc.RemoveTrack(a.sender)
			a.pub.removeTap(a.tap)
			delete(c.audio, id)
			changed = true
		}
	}
	c.mu.Unlock()
	if c.addOuts(pc) > 0 {
		changed = true
	}
	if !changed {
		return
	}
	if len(pc.GetTransceivers()) > relaySectionLimit {
		// Too many closed sections have piled up: start the connection afresh.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = c.openUp(ctx)
		return
	}
	offer, err := pc.CreateOffer(nil)
	if err == nil {
		err = pc.SetLocalDescription(offer)
	}
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	answer, err := c.up.Restart(ctx, "up", *pc.LocalDescription())
	if err != nil {
		go c.upLost(pc)
		return
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		go c.upLost(pc)
	}
}

// Close ends the relay link and forgets what it carried.
func (c *Cascade) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	outs := c.outs
	c.outs = map[string]*layeredOut{}
	audio := c.audio
	c.audio = map[string]*audioOut{}
	rpUp, rpDown := c.rpUp, c.rpDown
	upPC, downPC := c.upPC, c.downPC
	c.mu.Unlock()
	for _, o := range outs {
		o.pub.removeSub(o)
	}
	for _, a := range audio {
		a.pub.removeTap(a.tap)
	}
	_ = c.up.Leave()
	for _, rp := range []*peer{rpUp, rpDown} {
		if rp != nil {
			rp.close()
		}
	}
	for _, pc := range []*webrtc.PeerConnection{upPC, downPC} {
		if pc != nil {
			_ = pc.Close()
		}
	}
	c.r.mu.Lock()
	if c.r.cascade == c {
		c.r.cascade = nil
	}
	c.r.mu.Unlock()
}

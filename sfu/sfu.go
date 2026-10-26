// Package sfu is a selective forwarding unit on Pion: every participant sends
// their media to the server once, and the server forwards each track to
// everyone else in the room.
//
// Video is simulcast. A browser publishes the same camera as up to three layers
// (rids q, h, f: small, medium, full). The server keeps all of them and gives
// each subscriber, for each person, the one layer their link and screen can use
// (see adapt.go), switching between layers at keyframes without the subscriber
// noticing (see forwarder.go). A publisher that does not use simulcast is one
// layer. Video is VP8; audio is Opus.
//
// It is transport-neutral. The server never decides how a participant hears
// from it; it calls a Signaler, and the caller (the REF resource) delivers the
// SDP and ICE over the realtime hub. Participants send their first offer with
// Join and answer the server's later offers with Answer.
//
// A room lives in one process: media cannot be split across nodes without
// cascading SFUs. In a cluster, route every request for a room to one node
// (hash the room id at the load balancer); the call state itself is in SQL and
// is shared by all nodes.
package sfu

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/interceptor/pkg/cc"
	"github.com/pion/interceptor/pkg/gcc"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// Errors.
var (
	ErrRoomFull    = errors.New("sfu: the room is full")
	ErrNoPeer      = errors.New("sfu: no such participant")
	ErrClosed      = errors.New("sfu: server closed")
	ErrNegotiating = errors.New("sfu: a negotiation is in progress; retry")
	ErrNoOffer     = errors.New("sfu: there is no offer to answer")
	ErrBadPrefs    = errors.New("sfu: invalid preferences")
	// ErrE2EERequired is returned to a participant who joins an end-to-end
	// encrypted room without declaring that their media is encrypted.
	ErrE2EERequired = errors.New("sfu: this room is end-to-end encrypted")
)

// Signaler delivers the server's signaling to a participant.
type Signaler interface {
	// Offer sends a server-initiated offer (the room's tracks changed). The
	// participant must reply through Server.Answer. It may be sent again if no
	// answer arrives, so it must be safe to deliver twice.
	Offer(user, room string, offer webrtc.SessionDescription) error
	// Candidate sends a server ICE candidate.
	Candidate(user, room string, c webrtc.ICECandidateInit) error
}

// defaultICEKeepAlive is how often the server sends a connectivity check on a
// working connection. See Config.ICEKeepAlive.
var defaultICEKeepAlive = 2 * time.Second // Pion's own default

// Config tunes the server.
type Config struct {
	ICEServers []webrtc.ICEServer
	// UDPPortMin and UDPPortMax confine media to a range, so a firewall can
	// allow it. Zero leaves the choice to the OS.
	UDPPortMin, UDPPortMax uint16
	// PublicIPs are advertised as host candidates (NAT 1:1), for a server
	// behind a static NAT. Empty for a server with a public address.
	PublicIPs []string
	// MaxPeers is the most participants in one room. Default 50.
	MaxPeers int
	// MaxRooms bounds rooms on this node. Default 1000.
	MaxRooms int
	// LastNVideo and LastNAudio are how many people's video and audio each
	// viewer is sent in a room that sets no policy of its own: the people who
	// spoke last. 0 sends everyone (see Policy).
	LastNVideo, LastNAudio int
	// ReconnectGrace is how long a participant whose connection failed (a
	// network switch, a tunnel, a closed laptop lid) keeps their place and their
	// published tracks while they reconnect with an ICE restart. Default 45s.
	ReconnectGrace time.Duration
	// ReadyTimeout is how long, after a Join, the server holds its first offer
	// for the participant's Ready call before sending it regardless. Default 3s.
	ReadyTimeout time.Duration
	// OfferTimeout is how long a server offer waits for its answer before it is
	// sent again; the gap doubles on each repeat, up to eightfold. Default 6s.
	OfferTimeout time.Duration
	// InitialKbps is the bandwidth assumed for a new subscriber until the
	// estimator has seen their link. Default 600.
	InitialKbps int
	// ICEDisconnectedTimeout, ICEFailedTimeout and ICEKeepAlive tune how quickly
	// a silent path is declared disconnected and then failed (Pion's defaults are
	// 5 s, 25 s and 2 s). A failed connection is not the end of a participant:
	// they keep their place for ReconnectGrace, so ReconnectGrace should exceed
	// ICEFailedTimeout by the time a client needs to notice and restart.
	ICEDisconnectedTimeout, ICEFailedTimeout, ICEKeepAlive time.Duration
	// NetworkTypes limits the transports the server offers: "udp4", "udp6". Empty
	// means both. A server with no usable IPv6 address does better to say udp4:
	// every candidate pair that cannot work is a connectivity check wasted, and
	// after a network change those checks are what the client waits for.
	NetworkTypes []string
	// Interfaces, when set, is the only list of network interfaces whose addresses
	// the server offers (for example ["eth0"]). Empty means every interface.
	Interfaces []string
	// RecordDir is where recordings are written. Empty disables recording.
	RecordDir string
	// RecordLayer picks which video layer is recorded: "highest" (the default)
	// follows the best layer that is live; "lowest" records the smallest. For a
	// VP9 SVC publisher "highest" stores every spatial layer, which libvpx and
	// browsers play as one picture but ffmpeg's native decoder shows layer by
	// layer; "lowest" stores one layer that every decoder plays alike.
	RecordLayer string
	// RecordMinFree refuses to start a recording, and stops one under way, when
	// the recording directory has less than this many bytes free (0: no check).
	// RecordMaxDuration stops a recording after this long (0: no limit).
	RecordMinFree     uint64
	RecordMaxDuration time.Duration
	// Loopback includes loopback candidates; for tests only.
	Loopback bool

	adapt    *adaptCfg                           // tests shorten the hold times
	estimate func(room, user string) (int, bool) // tests stand in for the estimator
}

// Server is the SFU.
type Server struct {
	cfg Config
	api *webrtc.API
	sig Signaler

	pcMu  sync.Mutex // serializes PeerConnection creation, to pair each with its estimator
	estCh chan cc.BandwidthEstimator

	mu     sync.Mutex
	rooms  map[string]*room
	closed bool
	pol    policies

	stop chan struct{}
	wg   sync.WaitGroup
}

// New returns an SFU that signals through sig.
func New(cfg Config, sig Signaler) (*Server, error) {
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = 50
	}
	if cfg.MaxRooms <= 0 {
		cfg.MaxRooms = 1000
	}
	if cfg.ReconnectGrace <= 0 {
		cfg.ReconnectGrace = 45 * time.Second
	}
	if cfg.OfferTimeout <= 0 {
		cfg.OfferTimeout = 6 * time.Second
	}
	if cfg.InitialKbps <= 0 {
		cfg.InitialKbps = 600
	}
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = 3 * time.Second
	}
	me := &webrtc.MediaEngine{}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1"},
		PayloadType:        111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, err
	}
	// Video: VP8, VP9 and H.264, the codecs whose keyframes and picture counters
	// the layer switching understands (codec.go). AV1 is deliberately absent: its
	// layers are described by a dependency descriptor this does not parse.
	fb := []webrtc.RTCPFeedback{{Type: "goog-remb"}, {Type: "ccm", Parameter: "fir"}, {Type: "nack"}, {Type: "nack", Parameter: "pli"}}
	for _, c := range []webrtc.RTPCodecParameters{
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000, RTCPFeedback: fb}, PayloadType: 96},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP9, ClockRate: 90000, SDPFmtpLine: "profile-id=0", RTCPFeedback: fb}, PayloadType: 98},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, RTCPFeedback: fb,
			SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"}, PayloadType: 106},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, RTCPFeedback: fb,
			SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"}, PayloadType: 102},
		{RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, RTCPFeedback: fb,
			SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f"}, PayloadType: 125},
	} {
		if err := me.RegisterCodec(c, webrtc.RTPCodecTypeVideo); err != nil {
			return nil, err
		}
	}
	// Simulcast identifies a layer by these extensions; without them the
	// publisher's layers cannot be told apart.
	for _, uri := range []string{
		"urn:ietf:params:rtp-hdrext:sdes:mid",
		"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
		"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
	} {
		if err := me.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: uri}, webrtc.RTPCodecTypeVideo); err != nil {
			return nil, err
		}
	}
	if err := me.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: audioLevelURI}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, err
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, sig: sig, rooms: map[string]*room{}, stop: make(chan struct{}), estCh: make(chan cc.BandwidthEstimator, 4)}
	// A bandwidth estimate for each subscriber (Google congestion control over
	// transport-wide feedback), which is what the layer choice is made from.
	ccf, err := cc.NewInterceptor(func() (cc.BandwidthEstimator, error) {
		return gcc.NewSendSideBWE(gcc.SendSideBWEInitialBitrate(cfg.InitialKbps * 1000))
	})
	if err != nil {
		return nil, err
	}
	ccf.OnNewPeerConnection(func(_ string, e cc.BandwidthEstimator) {
		select {
		case s.estCh <- e:
		default:
		}
	})
	ir.Add(ccf)
	if err := webrtc.ConfigureTWCCHeaderExtensionSender(me, ir); err != nil {
		return nil, err
	}

	se := webrtc.SettingEngine{LoggerFactory: quietPacer{logging.NewDefaultLoggerFactory()}}
	if cfg.UDPPortMax != 0 {
		if err := se.SetEphemeralUDPPortRange(cfg.UDPPortMin, cfg.UDPPortMax); err != nil {
			return nil, err
		}
	}
	if len(cfg.PublicIPs) > 0 {
		se.SetNAT1To1IPs(cfg.PublicIPs, webrtc.ICECandidateTypeHost)
	}
	if cfg.Loopback {
		se.SetIncludeLoopbackCandidate(true)
	}
	nets := []webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6}
	if len(cfg.NetworkTypes) > 0 {
		nets = nets[:0]
		for _, n := range cfg.NetworkTypes {
			switch n {
			case "udp4":
				nets = append(nets, webrtc.NetworkTypeUDP4)
			case "udp6":
				nets = append(nets, webrtc.NetworkTypeUDP6)
			default:
				return nil, fmt.Errorf("sfu: network type %q is not udp4 or udp6", n)
			}
		}
	}
	se.SetNetworkTypes(nets)
	// By default every interface is offered. A deployment that knows which one
	// faces its clients says so, and nothing else is gathered. (Filtering
	// loopback, link-local and virtual interfaces by default was measured and made
	// connection switches slower, not faster.)
	if len(cfg.Interfaces) > 0 {
		se.SetInterfaceFilter(func(name string) bool { return slices.Contains(cfg.Interfaces, name) })
	}
	disc, fail, keep := cfg.ICEDisconnectedTimeout, cfg.ICEFailedTimeout, cfg.ICEKeepAlive
	if disc <= 0 {
		disc = 5 * time.Second // Pion's own defaults, spelt out because the three go together
	}
	if fail <= 0 {
		fail = 25 * time.Second
	}
	if keep <= 0 {
		keep = defaultICEKeepAlive
	}
	se.SetICETimeouts(disc, fail, keep)
	s.api = webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se))
	s.wg.Add(1)
	go s.housekeeping()
	return s, nil
}

// ---------------------------------------------------------------------------
// Rooms, publishers, subscribers
// ---------------------------------------------------------------------------

// layer is one simulcast layer of a published track.
type layer struct {
	rid     string
	ssrc    webrtc.SSRC
	bytes   atomic.Uint64
	lastPkt atomic.Int64 // unix nanos
	kbps    atomic.Int64
	lastAsk atomic.Int64
	prev    uint64 // housekeeping only
}

// layerLiveWindow is how long a layer may be silent and still count as live. A
// publisher whose uplink cannot carry the top layer stops sending it; its
// subscribers must notice and move down.
const layerLiveWindow = 1500 * time.Millisecond

type published struct {
	id    string
	owner *peer
	who   string // the person it belongs to: the owner, or for a relayed track the original publisher
	rids  bool   // the publisher sent RID-tagged simulcast streams
	kind  webrtc.RTPCodecType
	codec webrtc.RTPCodecCapability

	// audio is forwarded as received, through one track every subscriber binds.
	audio *webrtc.TrackLocalStaticRTP

	// video: the live layers and the subscribers fed from them.
	vcodec  codecKind
	svc     bool // one stream whose packets carry spatial layers (VP9 SVC)
	lmu     sync.RWMutex
	layers  map[string]*layer
	smu     sync.RWMutex
	subs    []layerSink
	readers atomic.Int32

	// sample is the start of a recent packet payload exactly as the server holds
	// it, for the self-audit (see Server.Sample).
	sample atomic.Pointer[[]byte]
	seen   atomic.Uint64

	tapMu sync.RWMutex // audio listeners (the recorder)
	taps  []*tap
}

// tap is a listener on a published audio track.
type tap struct{ f func(*rtp.Packet) }

// note keeps the start of every 15th payload, so a participant can be shown
// what the server actually holds of their own stream.
func (p *published) note(pkt *rtp.Packet) {
	if p.seen.Add(1)%15 != 1 {
		return
	}
	n := min(len(pkt.Payload), 48)
	b := append([]byte(nil), pkt.Payload[:n]...)
	p.sample.Store(&b)
}

// Sample returns the start of a recent payload of each of a participant's own
// tracks, as the server holds it: "video" and "audio", in hex. In an end-to-end
// encrypted call it is ciphertext after a few bytes the server needs to route
// the stream. It only ever shows a participant their own media.
func (s *Server) Sample(roomID, user string) (map[string]string, error) {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return nil, ErrNoPeer
	}
	out := map[string]string{}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pub := range r.pubs {
		if pub.owner == nil || pub.owner.user != user {
			continue
		}
		if b := pub.sample.Load(); b != nil {
			kind := "audio"
			if pub.kind == webrtc.RTPCodecTypeVideo {
				kind = "video"
			}
			out[kind] = fmt.Sprintf("%x", *b)
		}
	}
	return out, nil
}

// E2EE reports whether a room is end-to-end encrypted.
func (s *Server) E2EE(roomID string) bool {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	return r != nil && r.e2ee.Load()
}

func (p *published) addTap(f func(*rtp.Packet)) *tap {
	t := &tap{f: f}
	p.tapMu.Lock()
	p.taps = append(append([]*tap{}, p.taps...), t)
	p.tapMu.Unlock()
	return t
}

func (p *published) removeTap(t *tap) {
	p.tapMu.Lock()
	next := make([]*tap, 0, len(p.taps))
	for _, o := range p.taps {
		if o != t {
			next = append(next, o)
		}
	}
	p.taps = next
	p.tapMu.Unlock()
}

func (p *published) addSub(f layerSink) {
	p.smu.Lock()
	p.subs = append(append([]layerSink(nil), p.subs...), f)
	p.smu.Unlock()
}

func (p *published) removeSub(f layerSink) {
	p.smu.Lock()
	next := make([]layerSink, 0, len(p.subs))
	for _, s := range p.subs {
		if s != f {
			next = append(next, s)
		}
	}
	p.subs = next
	p.smu.Unlock()
}

func (p *published) fanout(rid string, pkt *rtp.Packet) {
	p.smu.RLock()
	subs := p.subs
	p.smu.RUnlock()
	for _, f := range subs {
		f.push(rid, pkt)
	}
}

// askKeyframe requests a keyframe of one layer from the publisher.
func (p *published) askKeyframe(rid string) {
	p.lmu.RLock()
	l := p.layers[rid]
	p.lmu.RUnlock()
	if l == nil || p.owner == nil {
		return
	}
	now := time.Now().UnixNano()
	if now-l.lastAsk.Load() < int64(150*time.Millisecond) {
		return
	}
	l.lastAsk.Store(now)
	_ = p.owner.pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(l.ssrc)}})
}

// layerInfos describes the layers lowest quality first.
func (p *published) layerInfos(now time.Time) []layerInfo {
	p.lmu.RLock()
	defer p.lmu.RUnlock()
	out := make([]layerInfo, 0, len(p.layers))
	for rid, l := range p.layers {
		out = append(out, layerInfo{
			RID: rid, Kbps: int(l.kbps.Load()),
			Active: now.UnixNano()-l.lastPkt.Load() < int64(layerLiveWindow),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := rankOf(out[i].RID), rankOf(out[j].RID); ri != rj {
			return ri < rj
		}
		return out[i].RID < out[j].RID
	})
	if p.svc {
		// Spatial layers build on each other: receiving layer N means receiving
		// everything below it, so a layer costs the sum.
		sum := 0
		for i := range out {
			sum += out[i].Kbps
			out[i].Kbps = sum
		}
	}
	return out
}

type room struct {
	id    string
	mu    sync.Mutex
	peers map[string]*peer
	pubs  map[string]*published

	srv     *Server
	pol     atomic.Pointer[Policy]    // set by the backend; nil takes the server's defaults
	sel     atomic.Pointer[selection] // who each viewer is sent; nil is everyone
	spoke   map[string]time.Time      // when each person last spoke (guarded by mu)
	cascade *Cascade                  // this node's link to the room's home node, if it is a leaf
	e2ee    atomic.Bool               // the room is end-to-end encrypted: the server never has the keys
	det     *speakerDetector          // housekeeping only
	rec     atomic.Pointer[recording]
	speaker atomic.Value // string: who is talking now
}

func (r *room) currentSpeaker() string {
	if v, ok := r.speaker.Load().(string); ok {
		return v
	}
	return ""
}

// peopleLocked counts the people in the room, not the relays to other nodes.
func (r *room) peopleLocked() int {
	n := 0
	for _, p := range r.peers {
		if !p.relay {
			n++
		}
	}
	return n
}

func (r *room) othersLocked(except string) []*peer {
	out := make([]*peer, 0, len(r.peers))
	for u, p := range r.peers {
		if u != except {
			out = append(out, p)
		}
	}
	return out
}

// subEntry is a subscriber's video from one publisher.
type subEntry struct {
	fwd    layerSink
	pub    *published
	sender *webrtc.RTPSender
}

type peer struct {
	user string
	room *room

	// A relay is another node's connection into this room (see cascade.go): it
	// is not a person. noOffer carries that node's participants to us (they are
	// the offerer, we never offer); the other direction carries ours to them (we
	// are the offerer). One-way connections cannot collide on renegotiation.
	relay     bool
	noOffer   bool
	relayNode string
	link      RelayLink // where to send this peer's offers and candidates, if it is a relay
	cascade   *Cascade  // set on a leaf's own relay peers
	pc        *webrtc.PeerConnection
	srv       *Server
	est       cc.BandwidthEstimator

	joined  time.Time
	estSeen atomic.Bool
	meter   meter // how loud this participant is speaking

	nmu     sync.Mutex // serializes negotiation
	senders map[string]*webrtc.RTPSender
	trans   map[string]*webrtc.RTPTransceiver
	pool    []*webrtc.RTPTransceiver // released download sections, ready for reuse
	dirty   bool
	ready   bool         // the participant has applied its join answer; offers may flow
	audioN  atomic.Int32 // audio senders, whose rate the budget reserves
	closing bool
	offer   *pendingOffer

	wasDown     atomic.Bool // the connection dropped; what comes back is damaged
	fmu         sync.Mutex  // the subscriber's video state
	fwds        map[string]*subEntry
	unavailable map[string]string // track id -> why this viewer cannot be sent it
	notes       []string          // things this participant should be told about their own stream
	prefs       Prefs
	ad          *adapter
	last        PeerStats

	gmu   sync.Mutex
	grace *time.Timer

	scheduled atomic.Bool // a renegotiation is already waiting its turn

	done chan struct{}
	once sync.Once
}

// pendingOffer is a server offer waiting for its answer.
type pendingOffer struct {
	sdp   webrtc.SessionDescription
	first time.Time // when it was first sent
	at    time.Time // when it was last sent
	tries int
}

// PeerNotifier is an optional extra for a Signaler: it is told whenever a person
// joins or leaves a room, with everyone in the room after the change. A person
// who is only reconnecting (inside ReconnectGrace) has not left.
type PeerNotifier interface {
	Peer(room, user string, joined bool, everyone []string) error
}

// SpeakerNotifier is an optional extra for a Signaler: it is told whenever the
// dominant speaker of a room changes ("" when nobody is speaking), with the
// participants to tell.
type SpeakerNotifier interface {
	Speaker(room, speaker string, participants []string) error
}

// Speaker returns who is currently speaking in a room, "" if no one is.
func (s *Server) Speaker(roomID string) string {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return ""
	}
	return r.currentSpeaker()
}

// Stats is a snapshot of the server.
type Stats struct {
	Rooms int `json:"rooms"`
	Peers int `json:"peers"`
}

// Stats counts rooms and participants (people, not relays between nodes).
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{}
	for _, r := range s.rooms {
		r.mu.Lock()
		if n := r.peopleLocked(); n > 0 {
			st.Rooms++
			st.Peers += n
		}
		r.mu.Unlock()
	}
	return st
}

// Peers lists the users in a room.
func (s *Server) Peers(roomID string) []string {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.peers))
	for u, p := range r.peers {
		if !p.relay {
			out = append(out, u)
		}
	}
	return out
}

// Close ends every room.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var all []*peer
	for _, r := range s.rooms {
		r.mu.Lock()
		for _, p := range r.peers {
			all = append(all, p)
		}
		r.mu.Unlock()
	}
	s.mu.Unlock()
	close(s.stop)
	for _, p := range all {
		p.close()
	}
	s.wg.Wait()
	return nil
}

// Join adds user to the room with their first offer and returns the answer.
// Joining again replaces the earlier connection (a reload, a second tab, or a
// client that gave up on an ICE restart and starts over).
func (s *Server) Join(ctx context.Context, roomID, user string, offer webrtc.SessionDescription) (webrtc.SessionDescription, error) {
	return s.join(ctx, roomID, user, offer, nil, false)
}

// JoinSecure joins a room whose media is end-to-end encrypted by the browsers,
// with keys this server never sees. The first secure join marks the room, and
// from then on a plain Join to it is refused: a participant who does not
// encrypt would put plaintext into a call everyone else believes is private.
// What the server holds of such a room is ciphertext: it cannot record it, and
// it does not forward H.264, whose framing cannot carry encrypted frames.
func (s *Server) JoinSecure(ctx context.Context, roomID, user string, offer webrtc.SessionDescription) (webrtc.SessionDescription, error) {
	return s.join(ctx, roomID, user, offer, nil, true)
}

// newPC makes a peer connection and collects the bandwidth estimator made with it.
func (s *Server) newPC() (*webrtc.PeerConnection, cc.BandwidthEstimator, error) {
	s.pcMu.Lock()
	defer s.pcMu.Unlock()
	select { // an estimator nobody collected must not be mistaken for this one
	case <-s.estCh:
	default:
	}
	pc, err := s.api.NewPeerConnection(webrtc.Configuration{ICEServers: s.cfg.ICEServers})
	var est cc.BandwidthEstimator
	select {
	case est = <-s.estCh:
	default:
	}
	return pc, est, err
}

func (s *Server) join(ctx context.Context, roomID, user string, offer webrtc.SessionDescription, relay *relayJoin, secure bool) (webrtc.SessionDescription, error) {
	if offer.Type != webrtc.SDPTypeOffer {
		return webrtc.SessionDescription{}, errors.New("sfu: Join needs an offer")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return webrtc.SessionDescription{}, ErrClosed
	}
	r := s.rooms[roomID]
	if r == nil {
		if len(s.rooms) >= s.cfg.MaxRooms {
			s.mu.Unlock()
			return webrtc.SessionDescription{}, ErrRoomFull
		}
		r = s.newRoom(roomID)
		s.rooms[roomID] = r
	}
	s.mu.Unlock()
	if secure {
		r.e2ee.Store(true)
	} else if relay == nil && r.e2ee.Load() {
		s.releaseRoom(r)
		return webrtc.SessionDescription{}, ErrE2EERequired
	}
	// A Join that fails must not leave the room it just created behind.
	joined := false
	defer func() {
		if !joined {
			s.releaseRoom(r)
		}
	}()

	r.mu.Lock()
	old := r.peers[user]
	if old == nil && relay == nil && r.peopleLocked() >= r.effective(s.cfg).MaxPeers {
		r.mu.Unlock()
		return webrtc.SessionDescription{}, ErrRoomFull
	}
	r.mu.Unlock()
	if old != nil {
		old.close()
	}

	pc, est, err := s.newPC()
	if err != nil {
		return webrtc.SessionDescription{}, err
	}
	cfg := defaultAdaptCfg()
	if s.cfg.adapt != nil {
		cfg = *s.cfg.adapt
	}
	p := &peer{
		user: user, room: r, pc: pc, srv: s, est: est, joined: time.Now(),
		senders: map[string]*webrtc.RTPSender{}, trans: map[string]*webrtc.RTPTransceiver{}, fwds: map[string]*subEntry{}, unavailable: map[string]string{}, ad: newAdapter(cfg),
		prefs: Prefs{Streams: map[string]StreamPref{}}, done: make(chan struct{}),
	}
	if relay != nil {
		p.relay, p.noOffer, p.relayNode, p.link = true, relay.up, relay.node, relay.back
	}
	if est != nil {
		est.OnTargetBitrateChange(func(int) { p.estSeen.Store(true) })
	}

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			p.sendCandidate(c.ToJSON())
		}
	})
	pc.OnConnectionStateChange(p.onState)
	pc.OnTrack(func(remote *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) { p.onTrack(remote, receiver) })

	if err := pc.SetRemoteDescription(offer); err != nil {
		_ = pc.Close()
		return webrtc.SessionDescription{}, fmt.Errorf("sfu: offer: %w", err)
	}
	answer, err := pc.CreateAnswer(nil)
	if err == nil {
		err = pc.SetLocalDescription(answer) // candidates trickle through the Signaler
	}
	if err != nil {
		_ = pc.Close()
		return webrtc.SessionDescription{}, fmt.Errorf("sfu: answer: %w", err)
	}

	r.mu.Lock()
	r.peers[user] = p
	r.mu.Unlock()
	joined = true
	if relay == nil {
		s.announce(r, user, true)
	}
	// Existing tracks reach the newcomer by a server offer, which the newcomer
	// answers like any other renegotiation. But not yet: the newcomer is still
	// applying the answer we are about to return, and an offer that overtook it
	// (they travel by different routes) would meet a participant mid-negotiation.
	// They say Ready when done; a client that never does is served after a delay.
	time.AfterFunc(s.cfg.ReadyTimeout, p.markReady)
	return *pc.LocalDescription(), nil
}

// Ready tells the server a participant has applied the answer to its Join, so
// the server may now send the offers it has been holding.
func (s *Server) Ready(roomID, user string) error {
	p := s.find(roomID, user)
	if p == nil {
		return ErrNoPeer
	}
	p.markReady()
	return nil
}

func (p *peer) markReady() {
	p.nmu.Lock()
	if p.ready || p.closing {
		p.nmu.Unlock()
		return
	}
	p.ready = true
	p.nmu.Unlock()
	go p.renegotiate()
	// Someone who joins a call that is being recorded is told so at once.
	if rec := p.room.rec.Load(); rec != nil {
		if n, ok := p.srv.sig.(RecordingNotifier); ok {
			_ = n.Recording(p.room.id, true, rec.info.StartedBy, []string{p.user})
		}
	}
}

// releaseRoom forgets a room nobody is in.
func (s *Server) releaseRoom(r *room) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.peers) == 0 && s.rooms[r.id] == r {
		delete(s.rooms, r.id)
	}
}

func (s *Server) find(roomID, user string) *peer {
	s.mu.Lock()
	r := s.rooms[roomID]
	s.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peers[user]
}

// Answer applies a participant's answer to a server offer. An answer for an
// offer that is no longer outstanding (a duplicate, or one that crossed a
// resend) is reported as ErrNoOffer and is harmless.
func (s *Server) Answer(roomID, user string, answer webrtc.SessionDescription) error {
	p := s.find(roomID, user)
	if p == nil {
		return ErrNoPeer
	}
	if answer.Type != webrtc.SDPTypeAnswer {
		return errors.New("sfu: Answer needs an answer")
	}
	p.nmu.Lock()
	if p.pc.SignalingState() != webrtc.SignalingStateHaveLocalOffer {
		p.nmu.Unlock()
		return ErrNoOffer
	}
	err := p.pc.SetRemoteDescription(answer)
	if err == nil {
		p.offer = nil
	}
	again := p.dirty
	p.nmu.Unlock()
	if err != nil {
		return fmt.Errorf("sfu: answer: %w", err)
	}
	if again {
		go p.renegotiate()
	}
	return nil
}

// Restart applies a participant's ICE-restart offer and returns the answer. A
// participant whose network changed (Wi-Fi to cellular, a new address) sends one
// to move the existing connection to the new path; their tracks, and everyone's
// subscriptions to them, stay as they are. If a server offer is in flight,
// ErrNegotiating is returned and the participant retries after answering it.
func (s *Server) Restart(ctx context.Context, roomID, user string, offer webrtc.SessionDescription) (webrtc.SessionDescription, error) {
	p := s.find(roomID, user)
	if p == nil {
		return webrtc.SessionDescription{}, ErrNoPeer
	}
	if offer.Type != webrtc.SDPTypeOffer {
		return webrtc.SessionDescription{}, errors.New("sfu: Restart needs an offer")
	}
	p.nmu.Lock()
	if p.closing {
		p.nmu.Unlock()
		return webrtc.SessionDescription{}, ErrNoPeer
	}
	if p.pc.SignalingState() != webrtc.SignalingStateStable {
		p.nmu.Unlock()
		return webrtc.SessionDescription{}, ErrNegotiating
	}
	err := p.pc.SetRemoteDescription(offer)
	var answer webrtc.SessionDescription
	if err == nil {
		answer, err = p.pc.CreateAnswer(nil)
	}
	if err == nil {
		err = p.pc.SetLocalDescription(answer)
	}
	p.nmu.Unlock()
	if err != nil {
		return webrtc.SessionDescription{}, fmt.Errorf("sfu: restart: %w", err)
	}
	p.cancelGrace()
	go p.renegotiate()
	// The path under this connection changed: packets in flight were lost, in
	// both directions. Do not wait for anyone's decoder to notice.
	p.recoverMedia()
	return *p.pc.LocalDescription(), nil
}

// recoverMedia asks for fresh keyframes after the path under p's connection
// changed or came back from a drop. What p receives is damaged, so each of the
// videos sent to p is asked for; what p publishes is damaged for everyone
// watching, so each of p's videos is asked for on behalf of its viewers. The
// forwarders keep asking, once packets flow again, until a keyframe arrives.
func (p *peer) recoverMedia() {
	p.fmu.Lock()
	mine := make([]layerSink, 0, len(p.fwds))
	for _, e := range p.fwds {
		mine = append(mine, e.fwd)
	}
	p.fmu.Unlock()
	for _, f := range mine {
		f.expectKeyframe()
	}
	r := p.room
	r.mu.Lock()
	var owned []*published
	for _, pub := range r.pubs {
		if pub.owner == p {
			owned = append(owned, pub)
		}
	}
	r.mu.Unlock()
	for _, pub := range owned {
		pub.smu.RLock()
		subs := append([]layerSink(nil), pub.subs...)
		pub.smu.RUnlock()
		for _, f := range subs {
			f.expectKeyframe()
		}
	}
}

// Resync sends again the offer a participant is being waited on for. A
// participant calls it after reconnecting its signaling channel, which may have
// dropped the offer.
func (s *Server) Resync(roomID, user string) error {
	p := s.find(roomID, user)
	if p == nil {
		return ErrNoPeer
	}
	p.nmu.Lock()
	var o *webrtc.SessionDescription
	if p.offer != nil {
		d := p.offer.sdp
		o = &d
		p.offer.at = time.Now()
	}
	p.nmu.Unlock()
	if o != nil {
		return p.sendOffer(*o)
	}
	return nil
}

// Candidate adds a participant's ICE candidate.
func (s *Server) Candidate(roomID, user string, c webrtc.ICECandidateInit) error {
	p := s.find(roomID, user)
	if p == nil {
		return ErrNoPeer
	}
	return p.pc.AddICECandidate(c)
}

// Leave removes a participant and the tracks they published.
func (s *Server) Leave(roomID, user string) {
	if p := s.find(roomID, user); p != nil {
		p.close()
	}
}

// ---------------------------------------------------------------------------
// Connection state: a network switch must not end the call
// ---------------------------------------------------------------------------

func (p *peer) onState(st webrtc.PeerConnectionState) {
	switch st {
	case webrtc.PeerConnectionStateDisconnected:
		p.wasDown.Store(true)
	case webrtc.PeerConnectionStateConnected:
		p.cancelGrace()
		if p.wasDown.Swap(false) {
			p.recoverMedia() // the connection came back by itself, without a restart
		}
	case webrtc.PeerConnectionStateFailed:
		p.wasDown.Store(true)
		// Not the end. The participant may be mid-switch between networks and
		// about to ICE-restart; they keep their place until the grace runs out.
		p.startGrace()
	case webrtc.PeerConnectionStateClosed:
		p.close()
	}
}

func (p *peer) startGrace() {
	p.gmu.Lock()
	defer p.gmu.Unlock()
	if p.grace != nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	p.grace = time.AfterFunc(p.srv.cfg.ReconnectGrace, p.close)
}

func (p *peer) cancelGrace() {
	p.gmu.Lock()
	if p.grace != nil {
		p.grace.Stop()
		p.grace = nil
	}
	p.gmu.Unlock()
}

// ---------------------------------------------------------------------------
// Publishing
// ---------------------------------------------------------------------------

// onTrack forwards a track a participant publishes to the rest of the room.
// For simulcast video it is called once per layer.
func (p *peer) onTrack(remote *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	id := p.user + ":" + remote.ID()
	r := p.room
	r.mu.Lock()
	pub := r.pubs[id]
	fresh := pub == nil
	if fresh {
		pub = &published{id: id, owner: p, who: p.user, rids: remote.RID() != "", kind: remote.Kind(), codec: remote.Codec().RTPCodecCapability, layers: map[string]*layer{}}
		if p.relay {
			pub.who = remote.StreamID() // a relayed track belongs to whoever sent it from the other node
		}
		if k, ok := codecOf(pub.codec.MimeType); ok {
			pub.vcodec = k
		}
		if pub.kind == webrtc.RTPCodecTypeAudio {
			local, err := webrtc.NewTrackLocalStaticRTP(pub.codec, id, p.user)
			if err != nil {
				r.mu.Unlock()
				return
			}
			pub.audio = local
		}
		r.pubs[id] = pub
	}
	r.mu.Unlock()
	if pub.kind == webrtc.RTPCodecTypeVideo && pub.vcodec == codecH264 && r.e2ee.Load() {
		// H.264 frames are NAL units found by start codes; ciphertext can contain
		// them, so encrypted frames cannot ride in it. Say so and forward nothing.
		r.mu.Lock()
		if r.pubs[id] == pub {
			delete(r.pubs, id)
		}
		r.mu.Unlock()
		const note = "your H.264 video is not sent: end-to-end encrypted calls support VP8 and VP9"
		p.fmu.Lock()
		if !slices.Contains(p.notes, note) { // once, not once per simulcast layer
			p.notes = append(p.notes, note)
		}
		p.fmu.Unlock()
		for { // drain it
			if _, _, err := remote.ReadRTP(); err != nil {
				return
			}
		}
	}
	if fresh {
		if rec := r.rec.Load(); rec != nil {
			rec.attach(pub)
		}
	}

	if pub.kind == webrtc.RTPCodecTypeAudio {
		p.forwardAudio(pub, remote, receiver, fresh)
		return
	}

	if pub.vcodec == codecVP9 && remote.RID() == "" {
		pub.svc = true
		p.readSVC(pub, remote, fresh)
		return
	}
	rid := remote.RID()
	if rid == "" {
		rid = "f" // a publisher without simulcast is one full-quality layer
	}
	l := &layer{rid: rid, ssrc: remote.SSRC()}
	l.lastPkt.Store(time.Now().UnixNano())
	pub.lmu.Lock()
	pub.layers[rid] = l
	pub.lmu.Unlock()
	pub.readers.Add(1)
	if fresh {
		p.notifyOthers()
	}
	for {
		pkt, _, err := remote.ReadRTP()
		if err != nil {
			break
		}
		l.bytes.Add(uint64(len(pkt.Payload)))
		l.lastPkt.Store(time.Now().UnixNano())
		pub.note(pkt)
		pub.fanout(rid, pkt)
	}
	pub.lmu.Lock()
	delete(pub.layers, rid)
	pub.lmu.Unlock()
	p.publicationEnded(pub, id)
}

// publicationEnded runs when the last reader of a published track stops.
func (p *peer) publicationEnded(pub *published, id string) {
	r := p.room
	if pub.readers.Add(-1) == 0 {
		r.mu.Lock()
		if r.pubs[id] == pub {
			delete(r.pubs, id)
		}
		r.mu.Unlock()
		if rec := r.rec.Load(); rec != nil {
			rec.detach(pub)
		}
		p.notifyOthers()
	}
}

// readSVC reads a VP9 SVC stream: one SSRC whose packets are labelled with the
// spatial layer they belong to. Each packet is offered to subscribers under its
// layer's name, and the layers come and go with the packets that carry them.
func (p *peer) readSVC(pub *published, remote *webrtc.TrackRemote, fresh bool) {
	id := pub.id
	pub.readers.Add(1)
	if fresh {
		p.notifyOthers()
	}
	seen := map[int]*layer{}
	for {
		pkt, _, err := remote.ReadRTP()
		if err != nil {
			break
		}
		sid := 0
		if d, ok := parseVP9(pkt.Payload); ok && d.hasLayer {
			sid = int(d.sid)
		}
		if sid > 2 {
			continue // more spatial layers than the three sizes this names
		}
		l := seen[sid]
		if l == nil {
			l = &layer{rid: ridOfSID(sid), ssrc: remote.SSRC()}
			seen[sid] = l
			pub.lmu.Lock()
			pub.layers[l.rid] = l
			pub.lmu.Unlock()
		}
		l.bytes.Add(uint64(len(pkt.Payload)))
		l.lastPkt.Store(time.Now().UnixNano())
		pub.note(pkt)
		pub.fanout(l.rid, pkt)
	}
	pub.lmu.Lock()
	for _, l := range seen {
		delete(pub.layers, l.rid)
	}
	pub.lmu.Unlock()
	p.publicationEnded(pub, id)
}

func (p *peer) forwardAudio(pub *published, remote *webrtc.TrackRemote, receiver *webrtc.RTPReceiver, fresh bool) {
	if fresh {
		p.notifyOthers()
	}
	var levelID uint8 // the negotiated id of the loudness extension, if the sender uses it
	if receiver != nil {
		for _, he := range receiver.GetParameters().HeaderExtensions {
			if he.URI == audioLevelURI {
				levelID = uint8(he.ID)
			}
		}
	}
	for {
		pkt, _, err := remote.ReadRTP()
		if err != nil {
			break
		}
		if levelID != 0 {
			if b := pkt.GetExtension(levelID); len(b) > 0 {
				p.meter.add(b[0])
			}
		}
		pub.note(pkt)
		// Not shared: the extensions carry this publisher's session ids.
		out := &rtp.Packet{Header: pkt.Header, Payload: pkt.Payload}
		out.Header.Extension, out.Header.Extensions = false, nil
		_ = pub.audio.WriteRTP(out) // fails while nobody is subscribed yet
		pub.tapMu.RLock()
		taps := pub.taps
		pub.tapMu.RUnlock()
		for _, t := range taps {
			t.f(pkt)
		}
	}
	r := p.room
	r.mu.Lock()
	if r.pubs[pub.id] == pub {
		delete(r.pubs, pub.id)
	}
	r.mu.Unlock()
	if rec := r.rec.Load(); rec != nil {
		rec.detach(pub)
	}
	p.notifyOthers()
}

func (p *peer) notifyOthers() {
	r := p.room
	r.reselect(time.Now(), false) // a newcomer may belong to the last N
	r.mu.Lock()
	others := r.othersLocked(p.user)
	r.mu.Unlock()
	for _, o := range others {
		o.scheduleRenegotiate()
	}
}

// ---------------------------------------------------------------------------
// Subscribing: negotiation
// ---------------------------------------------------------------------------

// renegotiate brings p's outgoing tracks in line with the room and, if
// anything changed, sends the participant an offer.
func (p *peer) renegotiate() {
	if p.cascade != nil {
		p.cascade.sync() // a leaf's own relay peer: its job is to carry local tracks upstream
		return
	}
	offer, ok := p.prepareOffer()
	if !ok {
		return
	}
	// Sent without holding the lock: a Signaler may answer synchronously, and
	// Answer takes the same lock.
	if err := p.sendOffer(offer); err != nil {
		_ = err // the offer stays pending; the retry in housekeeping resends it
	}
	p.adapt(time.Now())
}

// sendOffer delivers a server offer to a person through the Signaler, or to a
// relay through its link.
func (p *peer) sendOffer(offer webrtc.SessionDescription) error {
	if p.link != nil {
		return p.link.Offer(offer)
	}
	return p.srv.sig.Offer(p.user, p.room.id, offer)
}

func (p *peer) sendCandidate(c webrtc.ICECandidateInit) {
	if p.link != nil {
		_ = p.link.Candidate(c)
		return
	}
	_ = p.srv.sig.Candidate(p.user, p.room.id, c)
}

func (p *peer) prepareOffer() (webrtc.SessionDescription, bool) {
	p.nmu.Lock()
	defer p.nmu.Unlock()
	if p.closing || p.noOffer {
		return webrtc.SessionDescription{}, false // the up connection never carries media to the leaf
	}
	if p.relay && len(p.pc.GetTransceivers()) > relaySectionLimit {
		go p.close() // too many closed sections: the leaf rejoins on a fresh connection
		return webrtc.SessionDescription{}, false
	}
	if !p.ready {
		p.dirty = true // the join answer is still on its way; markReady will come back
		return webrtc.SessionDescription{}, false
	}
	if p.pc.SignalingState() != webrtc.SignalingStateStable {
		p.dirty = true // an offer is already out; revisit when it is answered
		return webrtc.SessionDescription{}, false
	}
	p.dirty = false

	r := p.room
	sel := r.sel.Load()
	r.mu.Lock()
	want := make(map[string]*published, len(r.pubs))
	for id, pub := range r.pubs {
		if pub.owner == p {
			continue
		}
		if p.relay && pub.owner.relay && pub.owner.relayNode == p.relayNode {
			continue // what a leaf sent us is not sent back to it
		}
		if !sel.allows(p, pub.who, pub.kind == webrtc.RTPCodecTypeVideo) {
			continue // outside the last N speakers, and not pinned
		}
		want[id] = pub
	}
	r.mu.Unlock()

	changed := false
	p.fmu.Lock()
	for id := range p.unavailable {
		if _, still := want[id]; !still {
			delete(p.unavailable, id)
		}
	}
	p.fmu.Unlock()
	for id, sender := range p.senders {
		if _, ok := want[id]; !ok {
			_ = p.pc.RemoveTrack(sender)
			if tr := p.trans[id]; tr != nil {
				// Not stopped: the section goes back to the pool and carries the
				// next video, so the SDP grows with the most videos shown at once,
				// not with how many people have come and gone.
				p.pool = append(p.pool, tr)
			}
			delete(p.senders, id)
			delete(p.trans, id)
			p.fmu.Lock()
			if e := p.fwds[id]; e != nil {
				e.pub.removeSub(e.fwd)
				delete(p.fwds, id)
			} else {
				p.audioN.Add(-1)
			}
			p.fmu.Unlock()
			changed = true
		}
	}
	for id, pub := range want {
		if _, ok := p.senders[id]; ok {
			continue
		}
		var track webrtc.TrackLocal
		var fwd layerSink
		if p.relay && pub.kind == webrtc.RTPCodecTypeVideo {
			// To another node a video goes whole: every layer, as the publisher sent it.
			out, err := newLayeredOut(p.pc, pub, id)
			if err != nil {
				continue
			}
			p.senders[id], p.trans[id] = out.sender, out.tr
			changed = true
			pub.addSub(out)
			p.fmu.Lock()
			p.fwds[id] = &subEntry{fwd: out, pub: pub, sender: out.sender}
			p.fmu.Unlock()
			out.start()
			continue
		}
		if pub.kind == webrtc.RTPCodecTypeAudio {
			track = pub.audio
		} else {
			local, err := webrtc.NewTrackLocalStaticRTP(pub.codec, id, pub.who)
			if err != nil {
				continue
			}
			track = local
			if pub.svc {
				fwd = newSVCForwarder(local, pub.askKeyframe, nil)
			} else {
				fwd = newCodecForwarder(pub.vcodec, local, pub.askKeyframe, nil)
			}
		}
		// Always a section of its own. AddTrack would reuse the participant's
		// upload section, which for a simulcast publisher carries rid
		// attributes: the forwarded stream would then be read as simulcast and
		// never demultiplexed.
		tr, err := p.reuseSection(track)
		if tr == nil {
			tr, err = p.pc.AddTransceiverFromTrack(track, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
		}
		if err != nil || tr == nil {
			continue
		}
		sender := tr.Sender()
		// A connection's video codecs are fixed by its first negotiation. If this
		// participant's browser did not offer the codec the publisher uses, the
		// section would be offered in some other codec and carry nothing. Say so,
		// rather than leave a sender that cannot work.
		if pub.kind == webrtc.RTPCodecTypeVideo && !senderCan(sender, pub.codec.MimeType) {
			_ = p.pc.RemoveTrack(sender)
			p.pool = append(p.pool, tr)
			p.fmu.Lock()
			p.unavailable[id] = "your browser did not offer " + pub.codec.MimeType + ", which " + pub.who + " is sending"
			p.fmu.Unlock()
			continue
		}
		p.fmu.Lock()
		delete(p.unavailable, id)
		p.fmu.Unlock()
		p.senders[id], p.trans[id] = sender, tr
		changed = true
		if fwd == nil {
			p.audioN.Add(1)
		} else {
			pub.addSub(fwd)
			p.fmu.Lock()
			p.fwds[id] = &subEntry{fwd: fwd, pub: pub, sender: sender}
			p.fmu.Unlock()
		}
		go readRTCP(sender, fwd)
	}
	if !changed {
		return webrtc.SessionDescription{}, false
	}
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		return webrtc.SessionDescription{}, false
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		return webrtc.SessionDescription{}, false
	}
	desc := *p.pc.LocalDescription()
	p.offer = &pendingOffer{sdp: desc, first: time.Now(), at: time.Now(), tries: 1}
	return desc, true
}

// relaySectionLimit is how many media sections a relay connection may have
// before it is replaced by a fresh one: sections of a relay are not reused, so
// a long-lived link would otherwise grow with every join and leave.
const relaySectionLimit = 48

// senderCan reports whether the sender's negotiated codecs include mime.
func senderCan(sender *webrtc.RTPSender, mime string) bool {
	for _, c := range sender.GetParameters().Codecs {
		if strings.EqualFold(c.MimeType, mime) {
			return true
		}
	}
	return false
}

// reuseSection attaches track to a released download section of the right kind,
// or returns nil if there is none. (Pion's own AddTrack reuse is not used: it
// would also pick the participant's upload section.)
func (p *peer) reuseSection(track webrtc.TrackLocal) (*webrtc.RTPTransceiver, error) {
	for i, tr := range p.pool {
		if tr.Kind() != track.Kind() {
			continue
		}
		sender, err := p.srv.api.NewRTPSender(track, p.pc.SCTP().Transport())
		if err != nil {
			return nil, err
		}
		if err := tr.SetSender(sender, track); err != nil {
			_ = sender.Stop()
			continue
		}
		p.pool = append(p.pool[:i], p.pool[i+1:]...)
		return tr, nil
	}
	return nil, nil
}

// readRTCP drains a sender's feedback, which the interceptors (retransmission,
// bandwidth estimation) need read to work, and turns a subscriber's request for
// a keyframe into a request to the publisher.
func readRTCP(sender *webrtc.RTPSender, fwd layerSink) {
	for {
		pkts, _, err := sender.ReadRTCP()
		if err != nil {
			return
		}
		if fwd == nil {
			continue
		}
		for _, pk := range pkts {
			switch pk.(type) {
			case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
				fwd.keyframeWanted()
			}
		}
	}
}

// close removes the peer and its tracks from the room.
func (p *peer) close() {
	p.once.Do(func() {
		p.cancelGrace()
		p.nmu.Lock()
		p.closing = true
		p.nmu.Unlock()
		close(p.done)
		_ = p.pc.Close()

		p.fmu.Lock()
		for _, e := range p.fwds {
			e.pub.removeSub(e.fwd)
		}
		p.fwds = map[string]*subEntry{}
		p.fmu.Unlock()

		r := p.room
		r.mu.Lock()
		removed := r.peers[p.user] == p
		if removed {
			delete(r.peers, p.user)
		}
		for id, pub := range r.pubs {
			if pub.owner == p {
				delete(r.pubs, id)
			}
		}
		others := r.othersLocked(p.user)
		empty := len(r.peers) == 0
		nobody := r.peopleLocked() == 0
		casc := r.cascade
		r.mu.Unlock()
		if removed && !p.relay {
			p.srv.announce(r, p.user, false)
		}
		r.reselect(time.Now(), false) // someone left: the next speaker takes their place
		for _, o := range others {
			o.scheduleRenegotiate()
		}
		if nobody && casc != nil && !p.relay {
			go casc.Close() // the last person left this node: stop relaying the room
		}
		if empty {
			p.srv.mu.Lock()
			r.mu.Lock()
			if len(r.peers) == 0 && p.srv.rooms[r.id] == r {
				delete(p.srv.rooms, r.id)
			}
			r.mu.Unlock()
			p.srv.mu.Unlock()
		}
	})
}

// quietPacer silences the congestion controller's pacer, which reports an
// error for every packet still queued when a connection closes, a routine
// event for a server whose participants come and go.
type quietPacer struct{ inner logging.LoggerFactory }

func (q quietPacer) NewLogger(scope string) logging.LeveledLogger {
	if scope == "pacer" {
		return silentLogger.NewLogger(scope)
	}
	return q.inner.NewLogger(scope)
}

var silentLogger = func() *logging.DefaultLoggerFactory {
	f := logging.NewDefaultLoggerFactory()
	f.DefaultLogLevel = logging.LogLevelDisabled
	return f
}()

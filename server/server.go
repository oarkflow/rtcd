// Package server is the call service.
//
// Everything a client can do is an operation (see ops.go), and an operation
// can be called two ways: over a WebSocket, which is how browsers and apps use
// the service (one connection carries their requests, the server's answers and
// every event pushed to them), or over plain HTTP, for backends that only need
// a request and a response and for minting the tokens browsers connect with.
// Both go through the same path: authentication, scope, rate limit, the
// operation, and an audit entry.
package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/calls"
	"github.com/oarkflow/rtcd/groups"
	"github.com/oarkflow/rtcd/sfu"
	"github.com/pion/webrtc/v4"
)

// Config configures a Server.
type Config struct {
	// DB holds calls and groups. Dialect is sqlite, postgres or mysql.
	DB      *sql.DB
	Dialect string
	Rebind  func(string) string
	// AuditDB holds the audit log. It defaults to DB, but with SQLite give it
	// a connection of its own so audit batches and call writes do not queue
	// behind each other.
	AuditDB *sql.DB
	// AuditFile, when set, also receives every audit entry as a JSON line.
	AuditFile string
	// AuditQueue is how many audit entries may wait to be stored before
	// operations start to wait for the store. Default 16384.
	AuditQueue int

	// Keys are the backend services allowed to use the API, each for one tenant.
	Keys []auth.ServiceKey
	// TokenSecret signs user tokens. Keep it as private as the keys.
	TokenSecret string
	// MaxTokenTTL caps the life of a user token. Default 1h.
	MaxTokenTTL time.Duration

	// AllowedOrigins are browser origins that may connect ("*" for any; tokens,
	// not cookies, authenticate, so this is about which pages may try).
	AllowedOrigins []string
	// InsecureHTTP accepts requests that did not arrive over TLS. By default
	// only TLS, or the same machine, is accepted. A proxy that ends TLS must
	// set X-Forwarded-Proto: https.
	InsecureHTTP bool

	// Calls.
	STUN, TURN  []string
	TURNSecret  string
	TURNTTL     time.Duration
	RingTimeout time.Duration
	MaxInvitees int
	// AllowPlaintext lets a call be made without end-to-end encryption.
	AllowPlaintext bool

	// Groups.
	MaxOwnedGroups, MaxGroupMembers int

	// SFU. UDPPortMin/Max bound the media ports; PublicIPs are what clients
	// should dial when this node is behind NAT.
	UDPPortMin, UDPPortMax uint16
	PublicIPs              []string
	// NetworkTypes is "udp4", "udp6" or both (the default).
	NetworkTypes []string
	// Interfaces limits which network interfaces the SFU offers addresses on; by
	// default every one except loopback, link-local, tunnels and virtual ones.
	Interfaces         []string
	MaxPeers, MaxRooms int
	// LastNVideo and LastNAudio are how many people's video and audio each
	// viewer is sent in a room (0: everyone). MaxRoomMembers is how many people a
	// managed room can admit.
	LastNVideo, LastNAudio, MaxRoomMembers int
	ReconnectGrace                         time.Duration
	OfferTimeout                           time.Duration
	InitialKbps                            int
	RecordDir                              string
	RecordLayer                            string

	// Connections.
	// Shards splits connections over independent hubs so connecting and
	// disconnecting never contend with delivery to other users. Default 32.
	Shards int
	// MaxConnections caps WebSocket connections on this node. Default 20000.
	MaxConnections int
	// MaxConnsPerUser caps one user's connections. Default 8.
	MaxConnsPerUser int
	// WriterQueue is how many events one connection may have waiting before it
	// is dropped as too slow. Default 256.
	WriterQueue int

	// Limits. OpsPerSecond is per user (all their connections together), and
	// RelayPerSecond is per user per call for signaling and key messages.
	OpsPerSecond, OpsBurst     float64
	RelayPerSecond, RelayBurst float64

	// Now is for tests.
	Now func() time.Time
}

func (c *Config) defaults() {
	if c.MaxTokenTTL <= 0 {
		c.MaxTokenTTL = time.Hour
	}
	if c.RecordLayer == "" {
		c.RecordLayer = "highest"
	}
	if c.Shards <= 0 {
		c.Shards = 32
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 20000
	}
	if c.MaxConnsPerUser <= 0 {
		c.MaxConnsPerUser = 8
	}
	if c.WriterQueue <= 0 {
		c.WriterQueue = 256
	}
	if c.OpsPerSecond == 0 {
		c.OpsPerSecond, c.OpsBurst = 200, 400
	}
	if c.RelayPerSecond == 0 {
		c.RelayPerSecond, c.RelayBurst = 100, 200
	}
	if c.AuditDB == nil {
		c.AuditDB = c.DB
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Server is the call service.
type Server struct {
	cfg    Config
	auth   *auth.Authenticator
	Store  *calls.Store
	Groups *groups.Store
	SFU    *sfu.Server
	Audit  *audit.Log

	ops      map[string]*opDef
	opLimit  *limiters
	rlLimit  *limiters
	anonFail *bucket // bounds the audit entries unauthenticated callers can cause
	hubs     *hubs
	tenants  sync.Map // call id -> tenant, for calls that have a room on this node
	glocks   [64]sync.Mutex

	opsOK, opsFailed, opsDenied atomic.Int64
	auditRefused                atomic.Int64
	anonSuppressed              atomic.Int64

	stop chan struct{}
	wg   sync.WaitGroup
}

// New opens the stores and starts the SFU.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.DB == nil {
		return nil, errors.New("rtcd: a database is required")
	}
	if len(cfg.Keys) == 0 {
		return nil, errors.New("rtcd: at least one service API key is required")
	}
	cfg.defaults()
	if cfg.RecordLayer != "highest" && cfg.RecordLayer != "lowest" {
		return nil, fmt.Errorf("rtcd: record_layer %q is not highest or lowest", cfg.RecordLayer)
	}
	if (cfg.UDPPortMin == 0) != (cfg.UDPPortMax == 0) || cfg.UDPPortMin > cfg.UDPPortMax {
		return nil, errors.New("rtcd: udp port min and max must both be set, min <= max")
	}
	if len(cfg.TURN) > 0 && cfg.TURNSecret == "" {
		return nil, errors.New("rtcd: TURN urls need a TURN secret; TURN without credentials is an open relay")
	}
	a, err := auth.New(cfg.Keys, cfg.TokenSecret, cfg.Now)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, auth: a, ops: map[string]*opDef{}, stop: make(chan struct{}),
		opLimit: newLimiters(cfg.OpsPerSecond, cfg.OpsBurst), rlLimit: newLimiters(cfg.RelayPerSecond, cfg.RelayBurst),
		anonFail: newBucket(20, 100, cfg.Now())}
	s.hubs = newHubs(s)

	s.Audit, err = audit.Open(ctx, audit.Config{DB: cfg.AuditDB, Dialect: cfg.Dialect, Rebind: cfg.Rebind, File: cfg.AuditFile, Queue: cfg.AuditQueue,
		OnError: func(err error) { fmt.Fprintf(os.Stderr, "rtcd: audit write failed, retrying: %v\n", err) }})
	if err != nil {
		return nil, err
	}
	s.Store, err = calls.Open(ctx, cfg.DB, calls.Options{
		Dialect: cfg.Dialect, Rebind: cfg.Rebind, Notifier: s,
		ICE:         calls.ICEConfig{STUN: cfg.STUN, TURN: cfg.TURN, Secret: cfg.TURNSecret, TTL: cfg.TURNTTL},
		RingTimeout: cfg.RingTimeout, MaxInvitees: cfg.MaxInvitees, MaxRoomMembers: cfg.MaxRoomMembers, RequireE2EE: !cfg.AllowPlaintext,
		Now: cfg.Now,
	})
	if err != nil {
		return nil, err
	}
	s.Groups, err = groups.Open(ctx, cfg.DB, groups.Options{Dialect: cfg.Dialect, Rebind: cfg.Rebind, Notifier: s,
		ValidUser: auth.ValidName, MaxOwned: cfg.MaxOwnedGroups, MaxMembers: cfg.MaxGroupMembers, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	var ice []webrtc.ICEServer
	if len(cfg.STUN) > 0 {
		ice = append(ice, webrtc.ICEServer{URLs: cfg.STUN})
	}
	s.SFU, err = sfu.New(sfu.Config{
		ICEServers: ice, UDPPortMin: cfg.UDPPortMin, UDPPortMax: cfg.UDPPortMax, PublicIPs: cfg.PublicIPs, NetworkTypes: cfg.NetworkTypes, Interfaces: cfg.Interfaces,
		MaxPeers: cfg.MaxPeers, MaxRooms: cfg.MaxRooms, LastNVideo: cfg.LastNVideo, LastNAudio: cfg.LastNAudio, ReconnectGrace: cfg.ReconnectGrace, OfferTimeout: cfg.OfferTimeout,
		InitialKbps: cfg.InitialKbps, RecordDir: cfg.RecordDir, RecordLayer: cfg.RecordLayer,
	}, s)
	if err != nil {
		return nil, err
	}
	s.registerOps()
	s.hubs.bind()
	s.wg.Add(1)
	go s.background()
	return s, nil
}

// Close stops the SFU, the connections and background work, and stores what the
// audit log still holds. The databases stay open.
func (s *Server) Close() error {
	select {
	case <-s.stop:
		return nil
	default:
		close(s.stop)
	}
	s.wg.Wait()
	s.hubs.close()
	err := s.SFU.Close()
	if aerr := s.Audit.Close(); err == nil {
		err = aerr
	}
	return err
}

// background ends calls that rang too long, closes connections whose tokens
// ran out, reports suppressed noise, and forgets idle rate-limit buckets.
func (s *Server) background() {
	defer s.wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for n := 0; ; n++ {
		select {
		case <-t.C:
			now := s.cfg.Now()
			s.hubs.expire(now)
			if n%2 == 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, _ = s.Store.Sweep(ctx)
				cancel()
			}
			if n%12 == 0 {
				s.opLimit.sweep(now, 5*time.Minute)
				s.rlLimit.sweep(now, 5*time.Minute)
			}
			if c := s.anonSuppressed.Swap(0); c > 0 {
				s.record(audit.Event{Action: "auth.suppressed", Outcome: audit.Denied, Code: "rate_limited", Meta: map[string]any{"count": c}})
			}
		case <-s.stop:
			return
		}
	}
}

// Mount registers the HTTP and WebSocket endpoints on app.
func (s *Server) Mount(app *fh.App) {
	app.Get("/healthz", func(c fh.Ctx) error { return c.Status(200).JSON(map[string]any{"ok": true}) })
	app.Get("/readyz", func(c fh.Ctx) error {
		ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
		defer cancel()
		if err := s.cfg.DB.PingContext(ctx); err != nil {
			return c.Status(503).JSON(map[string]any{"ok": false})
		}
		return c.Status(200).JSON(map[string]any{"ok": true})
	})
	app.Get("/v1/ws", s.upgrade)
	s.mountREST(app)
}

// Stats are what this node is carrying.
type Stats struct {
	Rooms, Peers, Connections             int
	OpsOK, OpsFailed, OpsDenied           int64
	EventsSent, EventsDropped             int64
	Audit                                 audit.Stats
	AuditRefused, SlowClientsDisconnected int64
}

// Stats returns the node's counters.
func (s *Server) Stats() Stats {
	st := s.SFU.Stats()
	sent, dropped := s.hubs.counters()
	return Stats{Rooms: st.Rooms, Peers: st.Peers, Connections: s.hubs.count(),
		OpsOK: s.opsOK.Load(), OpsFailed: s.opsFailed.Load(), OpsDenied: s.opsDenied.Load(),
		EventsSent: sent, EventsDropped: dropped, SlowClientsDisconnected: dropped,
		Audit: s.Audit.Stats(), AuditRefused: s.auditRefused.Load()}
}

// ---------------------------------------------------------------------------
// The SFU's messages to people become events.
// ---------------------------------------------------------------------------

func (s *Server) tenantOf(call string) (string, bool) {
	t, ok := s.tenants.Load(call)
	if !ok {
		return "", false
	}
	return t.(string), true
}

func (s *Server) emit(call, user, event string, v any) error {
	tenant, ok := s.tenantOf(call)
	if !ok {
		return errors.New("rtcd: no such room here")
	}
	raw, err := jsonMarshal(v)
	if err != nil {
		return err
	}
	return s.Notify(context.Background(), tenant, user, event, raw, "")
}

// Offer implements sfu.Signaler.
func (s *Server) Offer(user, call string, offer webrtc.SessionDescription) error {
	return s.emit(call, user, "sfu.offer", map[string]any{"call_id": call, "type": "offer", "sdp": offer.SDP})
}

// Candidate implements sfu.Signaler.
func (s *Server) Candidate(user, call string, c webrtc.ICECandidateInit) error {
	return s.emit(call, user, "sfu.candidate", map[string]any{"call_id": call, "candidate": c})
}

// Speaker implements sfu.SpeakerNotifier.
func (s *Server) Speaker(call, speaker string, participants []string) error {
	for _, u := range participants {
		_ = s.emit(call, u, "sfu.speaker", map[string]any{"call_id": call, "speaker": speaker})
	}
	return nil
}

// Recording implements sfu.RecordingNotifier.
func (s *Server) Recording(call string, on bool, by string, participants []string) error {
	tenant, _ := s.tenantOf(call)
	action := "sfu.record.stop"
	if on {
		action = "sfu.record.start"
	}
	s.record(audit.Event{Tenant: tenant, Actor: by, Action: action + ".notified", Target: call, Outcome: audit.OK, Transport: "server", Meta: map[string]any{"participants": len(participants)}})
	for _, u := range participants {
		_ = s.emit(call, u, "sfu.recording", map[string]any{"call_id": call, "recording": on, "by": by})
	}
	return nil
}

// left is called after a person leaves a call or the call ends.
func (s *Server) left(c calls.Call, user string) {
	if c.Status == calls.Ended {
		for _, u := range s.SFU.Peers(c.ID) {
			s.SFU.Leave(c.ID, u)
		}
		s.tenants.Delete(c.ID)
		return
	}
	s.SFU.Leave(c.ID, user)
}

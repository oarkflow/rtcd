// Command rtcd is the call service: audio and video calls (peer to peer or
// through a selective forwarding unit), end-to-end encrypted, behind an HTTP API
// that any backend can use.
//
//	rtcd -config rtcd.bcl
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/dbx/open"
	"github.com/oarkflow/rtcd/server"
)

// configKey is one backend service's key.
type configKey struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Tenant string `json:"tenant"`
}

// fileConfig is rtcd.bcl, see loadConfig.
type fileConfig struct {
	Listen  string `json:"listen"`
	NodeID  string `json:"node_id"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// InsecureHTTP serves signaling without TLS to anyone. Only for a service
	// behind a proxy that ends TLS and sets X-Forwarded-Proto, or for development.
	InsecureHTTP bool `json:"insecure_http"`

	Database struct {
		Driver string `json:"driver"` // sqlite, postgres or mysql
		DSN    string `json:"dsn"`
		// MaxOpen is the most connections this node holds (server databases;
		// default 20), and so the most queries it runs at once.
		MaxOpen     int    `json:"max_open"`
		MaxIdle     int    `json:"max_idle"`
		MaxLifetime string `json:"max_lifetime"`
	} `json:"database"`
	// Audit is where the audit log goes. By default it shares the database; with
	// SQLite give it a file of its own so audit batches and call writes do not
	// queue behind each other. File also writes every entry as a JSON line.
	Audit struct {
		DSN   string `json:"dsn"`
		File  string `json:"file"`
		Queue int    `json:"queue"`
	} `json:"audit"`

	Groups struct {
		MaxOwned   int `json:"max_owned"`
		MaxMembers int `json:"max_members"`
	} `json:"groups"`

	Limits struct {
		Shards          int     `json:"shards"`
		MaxConnections  int     `json:"max_connections"`
		MaxConnsPerUser int     `json:"max_connections_per_user"`
		MaxConnsTenant  int     `json:"max_connections_per_tenant"`
		WriterQueue     int     `json:"writer_queue"`
		OpsPerSecond    float64 `json:"ops_per_second"`
		OpsBurst        float64 `json:"ops_burst"`
		RelayPerSecond  float64 `json:"relay_per_second"`
		RelayBurst      float64 `json:"relay_burst"`
		ConvPerSecond   float64 `json:"conv_messages_per_second"`
		ConvBurst       float64 `json:"conv_message_burst"`
	} `json:"limits"`

	Keys           []configKey `json:"-"` // the key "name" { … } blocks
	TokenSecret    string      `json:"token_secret"`
	MaxTokenTTL    string      `json:"max_token_ttl"`
	AllowedOrigins []string    `json:"allowed_origins"`

	STUN           []string `json:"stun_urls"`
	TURN           []string `json:"turn_urls"`
	TURNSecret     string   `json:"turn_secret"`
	TURNTTL        string   `json:"turn_ttl"`
	RingTimeout    string   `json:"ring_timeout"`
	MaxInvitees    int      `json:"max_invitees"`
	AllowPlaintext bool     `json:"allow_plaintext"`

	UDPPortMin     int      `json:"udp_port_min"`
	UDPPortMax     int      `json:"udp_port_max"`
	PublicIPs      []string `json:"public_ips"`
	NetworkTypes   []string `json:"network_types"`
	Interfaces     []string `json:"interfaces"`
	MaxPeers       int      `json:"max_peers"`
	MaxRooms       int      `json:"max_rooms"`
	LastNVideo     int      `json:"last_n_video"`
	LastNAudio     int      `json:"last_n_audio"`
	MaxRoomMembers int      `json:"max_room_members"`
	ReconnectGrace string   `json:"reconnect_grace"`
	OfferTimeout   string   `json:"offer_timeout"`
	InitialKbps    int      `json:"initial_kbps"`
	RecordDir      string   `json:"record_dir"`
	RecordLayer    string   `json:"record_layer"`
	RecordMinFree  uint64   `json:"record_min_free_bytes"`
	RecordMaxTime  string   `json:"record_max_duration"`

	// Chat. Attachments are encrypted by the client; the service keeps bytes it
	// cannot read.
	AttachDir       string `json:"attach_dir"`
	MaxFileBytes    int64  `json:"max_file_bytes"`
	TenantFileBytes int64  `json:"tenant_file_bytes"`
	FileRetention   string `json:"file_retention"`
	MsgRetention    string `json:"message_retention"`
	MaxMessageBytes int    `json:"max_message_bytes"`
}

func dur(name, s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

// Build turns a file config into a server config.
func build(fc fileConfig) (server.Config, []*sql.DB, error) {
	var cfg server.Config
	if fc.Database.DSN == "" {
		if d := fc.Database.Driver; d != "" && d != "sqlite" {
			return cfg, nil, fmt.Errorf("database.dsn is required for %s", d)
		}
		fc.Database.DSN = "file:rtcd.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	for _, k := range fc.Keys {
		cfg.Keys = append(cfg.Keys, auth.ServiceKey{Name: k.Name, Key: k.Key, Tenant: k.Tenant})
	}
	cfg.TokenSecret = fc.TokenSecret
	cfg.TURNSecret = fc.TURNSecret
	var err error
	for _, d := range []struct {
		name string
		in   string
		out  *time.Duration
	}{
		{"max_token_ttl", fc.MaxTokenTTL, &cfg.MaxTokenTTL}, {"turn_ttl", fc.TURNTTL, &cfg.TURNTTL},
		{"ring_timeout", fc.RingTimeout, &cfg.RingTimeout}, {"reconnect_grace", fc.ReconnectGrace, &cfg.ReconnectGrace},
		{"offer_timeout", fc.OfferTimeout, &cfg.OfferTimeout},
		{"record_max_duration", fc.RecordMaxTime, &cfg.RecordMaxDuration}, {"file_retention", fc.FileRetention, &cfg.FileRetention}, {"message_retention", fc.MsgRetention, &cfg.MsgRetention},
	} {
		if *d.out, err = dur(d.name, d.in); err != nil {
			return cfg, nil, err
		}
	}
	for _, p := range []int{fc.UDPPortMin, fc.UDPPortMax} {
		if p < 0 || p > 65535 {
			return cfg, nil, errors.New("udp ports must be between 0 and 65535")
		}
	}
	cfg.AllowedOrigins, cfg.InsecureHTTP = fc.AllowedOrigins, fc.InsecureHTTP
	cfg.STUN, cfg.TURN, cfg.MaxInvitees, cfg.AllowPlaintext = fc.STUN, fc.TURN, fc.MaxInvitees, fc.AllowPlaintext
	cfg.UDPPortMin, cfg.UDPPortMax, cfg.PublicIPs = uint16(fc.UDPPortMin), uint16(fc.UDPPortMax), fc.PublicIPs
	cfg.NetworkTypes, cfg.Interfaces = fc.NetworkTypes, fc.Interfaces
	cfg.MaxPeers, cfg.MaxRooms, cfg.InitialKbps = fc.MaxPeers, fc.MaxRooms, fc.InitialKbps
	cfg.LastNVideo, cfg.LastNAudio, cfg.MaxRoomMembers = fc.LastNVideo, fc.LastNAudio, fc.MaxRoomMembers
	cfg.RecordDir, cfg.RecordLayer, cfg.RecordMinFree = fc.RecordDir, fc.RecordLayer, fc.RecordMinFree
	cfg.AttachDir, cfg.MaxFileBytes, cfg.TenantFileBytes, cfg.MaxMessageBytes = fc.AttachDir, fc.MaxFileBytes, fc.TenantFileBytes, fc.MaxMessageBytes
	cfg.NodeID = fc.NodeID
	life, err := dur("database.max_lifetime", fc.Database.MaxLifetime)
	if err != nil {
		return cfg, nil, err
	}
	pool := open.Pool{MaxOpen: fc.Database.MaxOpen, MaxIdle: fc.Database.MaxIdle, MaxLifetime: life}
	db, dialect, err := open.DB(fc.Database.Driver, fc.Database.DSN, pool)
	if err != nil {
		return cfg, nil, err
	}
	cfg.Dialect = dialect
	cfg.DB = db
	dbs := []*sql.DB{db}
	if fc.Audit.DSN != "" {
		adb, _, err := open.DB(fc.Database.Driver, fc.Audit.DSN, pool)
		if err != nil {
			return cfg, dbs, err
		}
		cfg.AuditDB = adb
		dbs = append(dbs, adb)
	}
	cfg.AuditFile, cfg.AuditQueue = fc.Audit.File, fc.Audit.Queue
	cfg.MaxOwnedGroups, cfg.MaxGroupMembers = fc.Groups.MaxOwned, fc.Groups.MaxMembers
	l := fc.Limits
	cfg.Shards, cfg.MaxConnections, cfg.MaxConnsPerUser, cfg.WriterQueue = l.Shards, l.MaxConnections, l.MaxConnsPerUser, l.WriterQueue
	cfg.MaxConnsPerTenant = l.MaxConnsTenant
	cfg.ConvPerSecond, cfg.ConvBurst = l.ConvPerSecond, l.ConvBurst
	cfg.OpsPerSecond, cfg.OpsBurst, cfg.RelayPerSecond, cfg.RelayBurst = l.OpsPerSecond, l.OpsBurst, l.RelayPerSecond, l.RelayBurst
	return cfg, dbs, nil
}

func main() {
	path := flag.String("config", "rtcd.bcl", "path to the BCL configuration")
	flag.Parse()
	if err := run(*path); err != nil {
		log.Fatalf("rtcd: %v", err)
	}
}

func run(path string) error {
	fc, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	cfg, dbs, err := build(fc)
	defer func() {
		for _, d := range dbs {
			d.Close()
		}
	}()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := server.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	// NewFast turns off write deadlines and has no read limits: slow-header
	// (slowloris) connections would be held open forever. Header and idle
	// deadlines apply to requests, not to an upgraded WebSocket.
	app := fh.NewFast(fh.WithReadHeaderTimeout(10*time.Second), fh.WithIdleTimeout(2*time.Minute), fh.WithMaxRequestBodySize(8<<20))
	srv.Mount(app)
	listen := fc.Listen
	if listen == "" {
		listen = ":8480"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if fc.TLSCert != "" || fc.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(fc.TLSCert, fc.TLSKey)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	} else if !fc.InsecureHTTP {
		log.Printf("rtcd: no TLS certificate: requests are accepted only from this machine, or from a proxy that sets X-Forwarded-Proto: https")
	}
	log.Printf("rtcd: serving on %s", ln.Addr())
	errc := make(chan error, 1)
	go func() { errc <- app.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Printf("rtcd: shutting down")
		return app.ShutdownWithTimeout(10 * time.Second)
	}
}

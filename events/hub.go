// Package events delivers call events to the people connected to this node.
//
// Each person has a private topic. A subscriber is a connection (a WebSocket or
// an SSE stream) with a bounded queue; one that cannot keep up is dropped, not
// waited for, and its client reconnects and asks for the call's state again.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
)

// ErrTooMany is returned when a topic already has the most connections allowed.
var ErrTooMany = errors.New("events: too many connections for this user")

// Config tunes a Hub. Zero values take the defaults.
type Config struct {
	// Queue is how many undelivered events one connection may hold. Default 256.
	Queue int
	// MaxPerTopic caps simultaneous connections for one user. Default 8.
	MaxPerTopic int
}

// Hub fans events out to subscribers by topic.
type Hub struct {
	cfg  Config
	mu   sync.RWMutex
	subs map[string]map[*Sub]struct{}
	seq  atomic.Uint64
	// remote, when set, also sends every event to other nodes.
	remote func(topic string, frame []byte)
}

// New makes an empty Hub.
func New(cfg Config) *Hub {
	if cfg.Queue <= 0 {
		cfg.Queue = 256
	}
	if cfg.MaxPerTopic <= 0 {
		cfg.MaxPerTopic = 8
	}
	return &Hub{cfg: cfg, subs: map[string]map[*Sub]struct{}{}}
}

// Sub is one connection's subscription.
type Sub struct {
	C       chan []byte // encoded frames, in order
	topic   string
	hub     *Hub
	done    chan struct{}
	once    sync.Once
	dropped atomic.Bool
}

// Done is closed when the subscription ends, whether by Close or by being
// dropped for falling behind.
func (s *Sub) Done() <-chan struct{} { return s.done }

// Dropped reports whether the hub ended the subscription because it fell behind.
func (s *Sub) Dropped() bool { return s.dropped.Load() }

// Close ends the subscription.
func (s *Sub) Close() {
	s.once.Do(func() {
		s.hub.mu.Lock()
		if m := s.hub.subs[s.topic]; m != nil {
			delete(m, s)
			if len(m) == 0 {
				delete(s.hub.subs, s.topic)
			}
		}
		s.hub.mu.Unlock()
		close(s.done)
	})
}

// Subscribe starts a subscription to one topic.
func (h *Hub) Subscribe(topic string) (*Sub, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs[topic]) >= h.cfg.MaxPerTopic {
		return nil, ErrTooMany
	}
	s := &Sub{C: make(chan []byte, h.cfg.Queue), topic: topic, hub: h, done: make(chan struct{})}
	if h.subs[topic] == nil {
		h.subs[topic] = map[*Sub]struct{}{}
	}
	h.subs[topic][s] = struct{}{}
	return s, nil
}

// Frame is what a connection receives.
type Frame struct {
	ID    uint64          `json:"id"`
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
	From  string          `json:"from,omitempty"`
}

// Notify delivers an event to everyone subscribed to topic, here and, if a
// backplane is attached, on other nodes. It implements calls.Notifier.
func (h *Hub) Notify(_ context.Context, topic, event string, data json.RawMessage, from string) error {
	frame, err := json.Marshal(Frame{ID: h.seq.Add(1), Event: event, Data: data, From: from})
	if err != nil {
		return err
	}
	h.Deliver(topic, frame)
	if h.remote != nil {
		h.remote(topic, frame)
	}
	return nil
}

// Deliver puts an already encoded frame on the local subscribers of topic.
func (h *Hub) Deliver(topic string, frame []byte) {
	h.mu.RLock()
	var slow []*Sub
	for s := range h.subs[topic] {
		select {
		case s.C <- frame:
		default:
			slow = append(slow, s)
		}
	}
	h.mu.RUnlock()
	for _, s := range slow {
		s.dropped.Store(true)
		s.Close()
	}
}

// OnPublish makes the hub hand every locally published event to f, so a
// backplane can carry it to other nodes. Events that arrive from other nodes
// are given to Deliver, which does not call f again.
func (h *Hub) OnPublish(f func(topic string, frame []byte)) { h.remote = f }

// Connections is how many subscriptions this node holds.
func (h *Hub) Connections() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, m := range h.subs {
		n += len(m)
	}
	return n
}

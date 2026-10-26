package server

import (
	"sync"
	"time"
)

// Rooms of this many people or fewer get every peer and speaker event at once.
// Larger rooms get them batched: a hundred people joining would otherwise send
// every one of them a hundred events, and a full writer queue closes the
// connection of someone who did nothing wrong.
const (
	fanoutSmall = 16
	fanoutWait  = 250 * time.Millisecond
)

// batcher collects peer changes and the latest speaker for one call and sends
// them to everyone in one event each.
type batcher struct {
	mu       sync.Mutex
	joined   map[string]bool
	left     map[string]bool
	everyone []string
	speaker  string
	listen   []string
	speakSet bool
	timer    *time.Timer
}

type fanout struct {
	s  *Server
	mu sync.Mutex
	m  map[string]*batcher
}

func newFanout(s *Server) *fanout { return &fanout{s: s, m: map[string]*batcher{}} }

func (f *fanout) get(call string) *batcher {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.m[call]
	if b == nil {
		b = &batcher{joined: map[string]bool{}, left: map[string]bool{}}
		f.m[call] = b
	}
	return b
}

// peer records a change. It reports false if the room is small enough to send at once.
func (f *fanout) peer(call, user string, joined bool, everyone []string) bool {
	if len(everyone) <= fanoutSmall && !f.pending(call) {
		return false
	}
	b := f.get(call)
	b.mu.Lock()
	if joined {
		b.joined[user] = true
		delete(b.left, user)
	} else {
		b.left[user] = true
		delete(b.joined, user)
	}
	b.everyone = everyone
	f.arm(call, b)
	b.mu.Unlock()
	return true
}

// pending reports whether a batch is waiting, so later changes keep their order.
func (f *fanout) pending(call string) bool {
	f.mu.Lock()
	b := f.m[call]
	f.mu.Unlock()
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.timer != nil
}

func (f *fanout) speaker(call, speaker string, participants []string) bool {
	if len(participants) <= fanoutSmall && !f.pending(call) {
		return false
	}
	b := f.get(call)
	b.mu.Lock()
	b.speaker, b.speakSet, b.listen = speaker, true, participants
	f.arm(call, b)
	b.mu.Unlock()
	return true
}

func (f *fanout) arm(call string, b *batcher) {
	if b.timer == nil {
		b.timer = time.AfterFunc(fanoutWait, func() { f.flush(call, b) })
	}
}

func (f *fanout) flush(call string, b *batcher) {
	b.mu.Lock()
	joined, left, everyone := keys(b.joined), keys(b.left), b.everyone
	speaker, speakSet, listen := b.speaker, b.speakSet, b.listen
	b.joined, b.left, b.speakSet, b.timer = map[string]bool{}, map[string]bool{}, false, nil
	b.mu.Unlock()
	if len(joined)+len(left) > 0 {
		ev := map[string]any{"call_id": call, "joined": joined, "left": left, "count": len(everyone)}
		for _, u := range everyone {
			_ = f.s.emit(call, u, "sfu.peers", ev)
		}
	}
	if speakSet {
		for _, u := range listen {
			_ = f.s.emit(call, u, "sfu.speaker", map[string]any{"call_id": call, "speaker": speaker})
		}
	}
	f.mu.Lock()
	b.mu.Lock()
	if b.timer == nil && len(b.joined)+len(b.left) == 0 && !b.speakSet {
		delete(f.m, call)
	}
	b.mu.Unlock()
	f.mu.Unlock()
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

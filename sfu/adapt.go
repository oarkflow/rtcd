package sfu

import (
	"sort"
	"time"
)

// Layer choice for one subscriber.
//
// Two rules decide everything here.
//
//  1. Everyone sees everyone. Every video the subscriber has not hidden gets at
//     least its lowest live layer, whatever the bandwidth. Pressure lowers
//     quality; it never removes a person from the screen. (Only the subscriber
//     can hide a tile, by asking.)
//  2. Quality moves cautiously. A drop is immediate, because a congested link
//     loses packets for everyone; a rise waits for the link to look stable, goes
//     one step at a time, and backs off after a rise that did not hold.

// layerInfo describes one simulcast layer of a published track.
type layerInfo struct {
	RID    string
	Kbps   int  // measured; a nominal figure until the layer has been measured
	Active bool // packets arrived recently
}

// streamIn is one video track as the allocator sees it.
type streamIn struct {
	ID       string
	Layers   []layerInfo // lowest quality first
	Max      string      // highest layer the subscriber wants; "" for no limit
	Hidden   bool        // the subscriber asked not to receive it
	Priority int         // higher is upgraded first (a pinned speaker)
}

// candidates are the live layers the subscriber may receive, lowest first.
// A layer above Max is excluded unless nothing at or below it is live: a
// picture bigger than asked for beats no picture.
func (s streamIn) candidates() []layerInfo {
	var live, wanted []layerInfo
	maxRank := rankOf(s.Max)
	for _, l := range s.Layers {
		if !l.Active {
			continue
		}
		live = append(live, l)
		if s.Max == "" || rankOf(l.RID) <= maxRank {
			wanted = append(wanted, l)
		}
	}
	if len(wanted) > 0 {
		return wanted
	}
	if len(live) > 0 {
		return live[:1]
	}
	return nil
}

// layerRank orders the conventional simulcast names; anything else sorts after
// them by name.
var layerRank = map[string]int{"q": 0, "h": 1, "f": 2}

func rankOf(rid string) int {
	if r, ok := layerRank[rid]; ok {
		return r
	}
	return 100 + int(hashRID(rid)%900)
}

func hashRID(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * 16777619
	}
	return h
}

// nominalKbps stands in for a layer that has not been measured yet.
func nominalKbps(rid string) int {
	switch rid {
	case "q":
		return 150
	case "h":
		return 500
	case "f":
		return 1200
	}
	return 500
}

func (l layerInfo) cost() int {
	if l.Kbps > 0 {
		return l.Kbps
	}
	return nominalKbps(l.RID)
}

// allocate picks a layer per stream for a budget in kbps. Streams that are
// hidden, or have no live layer, get "".
func allocate(streams []streamIn, budgetKbps int) map[string]string {
	order := make([]streamIn, len(streams))
	copy(order, streams)
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].Priority != order[j].Priority {
			return order[i].Priority > order[j].Priority
		}
		return order[i].ID < order[j].ID
	})
	out := make(map[string]string, len(order))
	pos := make(map[string]int, len(order))
	cands := make(map[string][]layerInfo, len(order))
	spent := 0
	for _, s := range order {
		out[s.ID] = ""
		if s.Hidden {
			continue
		}
		c := s.candidates()
		if len(c) == 0 {
			continue
		}
		cands[s.ID] = c
		out[s.ID] = c[0].RID // rule 1: everyone gets a picture, regardless of budget
		spent += c[0].cost()
	}
	// Raise quality one step at a time. Higher-priority tiers (a pinned
	// speaker) are raised as far as they can go before a lower tier gets
	// anything above its floor; within a tier the spare is shared round-robin,
	// so it does not all go to whoever sorts first.
	for lo := 0; lo < len(order); {
		hi := lo
		for hi < len(order) && order[hi].Priority == order[lo].Priority {
			hi++
		}
		tier := order[lo:hi]
		for changed := true; changed; {
			changed = false
			for _, s := range tier {
				c := cands[s.ID]
				if c == nil || pos[s.ID]+1 >= len(c) {
					continue
				}
				delta := c[pos[s.ID]+1].cost() - c[pos[s.ID]].cost()
				if delta > budgetKbps-spent {
					continue
				}
				pos[s.ID]++
				out[s.ID] = c[pos[s.ID]].RID
				spent += delta
				changed = true
			}
		}
		lo = hi
	}
	return out
}

// usageKbps is what forwarding the given choice costs.
func usageKbps(streams []streamIn, choice map[string]string) int {
	total := 0
	for _, s := range streams {
		for _, l := range s.Layers {
			if l.RID == choice[s.ID] && choice[s.ID] != "" {
				total += l.cost()
			}
		}
	}
	return total
}

// adaptCfg tunes how readily quality rises.
type adaptCfg struct {
	// UpgradeHold is how long the link must look stable after a drop before
	// quality rises again; StepHold is the wait between successive rises.
	UpgradeHold, StepHold time.Duration
	// TrialHold is the quiet time before a rise the estimator has not yet
	// justified; TrialPeriod is how long that rise has to hold.
	TrialHold, TrialPeriod time.Duration
	// MinBackoff and MaxBackoff bound the wait after a failed trial.
	MinBackoff, MaxBackoff time.Duration
}

func defaultAdaptCfg() adaptCfg {
	return adaptCfg{
		UpgradeHold: 4 * time.Second, StepHold: 2 * time.Second,
		TrialHold: 8 * time.Second, TrialPeriod: 6 * time.Second,
		MinBackoff: 10 * time.Second, MaxBackoff: 90 * time.Second,
	}
}

// adapter holds one subscriber's state across evaluations.
type adapter struct {
	cfg adaptCfg
	cur map[string]string

	stableSince time.Time
	lastDown    time.Time
	backoff     time.Duration
	trialEnd    time.Time
	trialStart  time.Time
	trialStream string
}

// trialSettle is how long a trial rise is left alone before it is judged: the
// estimator needs a moment of the higher rate to answer.
const trialSettle = 3 * time.Second

func newAdapter(cfg adaptCfg) *adapter {
	return &adapter{cfg: cfg, cur: map[string]string{}}
}

const unlimited = 1 << 30

// budgetKbps turns the estimator's figure into what video may use. unknown
// (estimate <= 0) means no estimator, hence no limit; capKbps is the
// subscriber's own data-saver ceiling.
func budgetKbps(estimateKbps, capKbps, audioKbps int) int {
	b := unlimited
	if estimateKbps > 0 {
		b = estimateKbps*85/100 - audioKbps
		if b < 0 {
			b = 0
		}
	}
	if capKbps > 0 && capKbps < b {
		b = capKbps
	}
	return b
}

// step evaluates one subscriber and returns the layer to forward per stream.
func (a *adapter) step(now time.Time, streams []streamIn, budget, estimateKbps int) map[string]string {
	if a.stableSince.IsZero() {
		a.stableSince = now
	}
	ideal := allocate(streams, budget)
	floor := allocate(streams, 0)
	next := make(map[string]string, len(streams))
	downgraded := false
	valid := map[string]streamIn{}
	for _, s := range streams {
		valid[s.ID] = s
	}
	for id := range a.cur {
		if _, ok := valid[id]; !ok {
			delete(a.cur, id)
		}
	}

	for _, s := range streams {
		cur := a.cur[s.ID]
		had := cur != "" // a stream that was hidden or gone starts again from the floor
		want := ideal[s.ID]
		trialing := s.ID == a.trialStream && !a.trialEnd.IsZero() && now.Before(a.trialStart.Add(trialSettle))
		switch {
		case !had:
			next[s.ID] = floor[s.ID] // start low and climb: the first picture is fast
		case want != "" && trialing && hasLive(s, cur):
			next[s.ID] = cur // a rise that is still settling is not judged yet
		case want == "" || !hasLive(s, cur) || rankOf(want) < rankOf(cur):
			next[s.ID] = want // hidden, gone, or over budget: act now
			if want != cur {
				downgraded = true
			}
		default:
			next[s.ID] = cur
		}
	}

	if downgraded {
		if !a.trialEnd.IsZero() && now.Before(a.trialEnd.Add(3*time.Second)) {
			// The rise we tried did not hold: wait longer before the next one.
			a.backoff = min(max(a.backoff*2, a.cfg.MinBackoff), a.cfg.MaxBackoff)
		}
		a.lastDown, a.stableSince, a.trialEnd, a.trialStream = now, now, time.Time{}, ""
	} else if !a.trialEnd.IsZero() && !now.Before(a.trialEnd) {
		a.backoff, a.trialEnd, a.trialStream = 0, time.Time{}, "" // the rise held
	}

	// At most one rise per evaluation, once the link has looked steady.
	ready := now.Sub(a.stableSince) >= a.cfg.StepHold &&
		now.Sub(a.lastDown) >= a.cfg.UpgradeHold && now.Sub(a.lastDown) >= a.backoff
	if ready && !downgraded {
		if id, rid := a.pickRise(streams, ideal, next); id != "" {
			next[id] = rid
			a.stableSince = now
		} else if now.Sub(a.lastDown) >= a.cfg.TrialHold && a.trialEnd.IsZero() &&
			(estimateKbps <= 0 || estimateKbps*100 >= usageKbps(streams, next)*95) {
			// The estimator has not justified a rise, but it may simply be
			// held down by how little we send. Try one step and see.
			if id, rid := a.pickHeadroom(streams, next); id != "" {
				next[id] = rid
				a.trialEnd, a.trialStart, a.trialStream = now.Add(a.cfg.TrialPeriod), now, id
				a.stableSince = now
			}
		}
	}
	a.cur = next
	return next
}

func hasLive(s streamIn, rid string) bool {
	for _, l := range s.Layers {
		if l.RID == rid && l.Active {
			return true
		}
	}
	return false
}

// pickRise finds the highest-priority stream whose ideal layer is above its
// current one, and returns the next layer up.
func (a *adapter) pickRise(streams []streamIn, ideal, cur map[string]string) (string, string) {
	for _, s := range byPriority(streams) {
		if ideal[s.ID] == "" || cur[s.ID] == "" || rankOf(ideal[s.ID]) <= rankOf(cur[s.ID]) {
			continue
		}
		if rid := nextLayer(s, cur[s.ID], ideal[s.ID]); rid != "" {
			return s.ID, rid
		}
	}
	return "", ""
}

// pickHeadroom finds a stream that could go up (within its Max) regardless of
// what the estimator says.
func (a *adapter) pickHeadroom(streams []streamIn, cur map[string]string) (string, string) {
	for _, s := range byPriority(streams) {
		c := s.candidates()
		if cur[s.ID] == "" || len(c) == 0 {
			continue
		}
		if rid := nextLayer(s, cur[s.ID], c[len(c)-1].RID); rid != "" {
			return s.ID, rid
		}
	}
	return "", ""
}

// nextLayer is the first live layer above from, not past limit.
func nextLayer(s streamIn, from, limit string) string {
	for _, l := range s.candidates() {
		if rankOf(l.RID) > rankOf(from) && rankOf(l.RID) <= rankOf(limit) {
			return l.RID
		}
	}
	return ""
}

func byPriority(streams []streamIn) []streamIn {
	out := make([]streamIn, len(streams))
	copy(out, streams)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

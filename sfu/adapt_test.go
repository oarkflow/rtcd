package sfu

import (
	"fmt"
	"testing"
	"time"
)

func qhf() []layerInfo {
	return []layerInfo{{"q", 150, true}, {"h", 500, true}, {"f", 1200, true}}
}

func streams(n int) []streamIn {
	out := make([]streamIn, n)
	for i := range out {
		out[i] = streamIn{ID: fmt.Sprintf("u%d", i), Layers: qhf()}
	}
	return out
}

func TestEveryoneIsSeenWhateverTheBudget(t *testing.T) {
	// The rule that matters most: no budget, however small, removes anyone.
	for _, budget := range []int{0, 1, 100, 1000, 100000, unlimited} {
		got := allocate(streams(12), budget)
		for id, rid := range got {
			if rid == "" {
				t.Fatalf("budget %d: %s has no picture", budget, id)
			}
		}
	}
	// With nothing spare, everyone is on the smallest layer.
	for id, rid := range allocate(streams(12), 0) {
		if rid != "q" {
			t.Fatalf("%s on %s with no budget, want q", id, rid)
		}
	}
	// With plenty, everyone is at full quality.
	for id, rid := range allocate(streams(3), unlimited) {
		if rid != "f" {
			t.Fatalf("%s on %s with unlimited budget, want f", id, rid)
		}
	}
}

func TestSpareBudgetIsSharedFairly(t *testing.T) {
	// 12 people: 12 x q = 1800. 1800 + 12 x 350 (q->h) = 6000 raises all to h
	// before anyone gets f.
	got := allocate(streams(12), 6000)
	for id, rid := range got {
		if rid != "h" {
			t.Fatalf("%s on %s; budget for everyone to reach h should not let one reach f first", id, rid)
		}
	}
	// A pinned speaker is raised first when the budget is tight.
	in := streams(4)
	in[2].Priority = 10
	got = allocate(in, 4*150+1050) // q for all, plus q->h->f for one (350+700)
	if got["u2"] != "f" || got["u0"] != "q" {
		t.Fatalf("pinned speaker should get the spare: %v", got)
	}
}

func TestHiddenAndMaxAreHonoured(t *testing.T) {
	in := streams(3)
	in[0].Hidden = true
	in[1].Max = "h"
	got := allocate(in, unlimited)
	if got["u0"] != "" || got["u1"] != "h" || got["u2"] != "f" {
		t.Fatalf("%v", got)
	}
	// A cap below every live layer still shows a picture.
	in[1].Layers = []layerInfo{{"q", 150, false}, {"h", 500, true}, {"f", 1200, true}}
	in[1].Max = "q"
	if got = allocate(in, unlimited); got["u1"] != "h" {
		t.Fatalf("asked for q, but only h and f are live: %v", got)
	}
}

func TestDeadLayerIsNeverChosen(t *testing.T) {
	in := streams(1)
	in[0].Layers[2].Active = false // the publisher's uplink dropped f
	if got := allocate(in, unlimited); got["u0"] != "h" {
		t.Fatalf("f is not arriving: %v", got)
	}
	in[0].Layers = []layerInfo{{"q", 0, false}, {"h", 0, false}, {"f", 0, false}}
	if got := allocate(in, unlimited); got["u0"] != "" {
		t.Fatalf("nothing is arriving: %v", got)
	}
}

func TestUnmeasuredLayersUseNominalRates(t *testing.T) {
	in := []streamIn{{ID: "a", Layers: []layerInfo{{"q", 0, true}, {"h", 0, true}, {"f", 0, true}}}}
	if usageKbps(in, map[string]string{"a": "h"}) != 500 {
		t.Fatal("nominal h should be 500 kbps")
	}
}

// run feeds the adapter a steady estimate for d, evaluating every 500 ms.
func run(a *adapter, now *time.Time, in []streamIn, estimate int, d time.Duration) map[string]string {
	var out map[string]string
	end := now.Add(d)
	for now.Before(end) {
		*now = now.Add(500 * time.Millisecond)
		out = a.step(*now, in, budgetKbps(estimate, 0, 0), estimate)
	}
	return out
}

func TestStartsLowThenClimbsOneStepAtATime(t *testing.T) {
	now := time.Unix(0, 0)
	a := newAdapter(defaultAdaptCfg())
	in := streams(2)
	first := a.step(now, in, budgetKbps(10000, 0, 0), 10000)
	if first["u0"] != "q" || first["u1"] != "q" {
		t.Fatalf("a new subscriber should begin on the smallest layer so video appears at once: %v", first)
	}
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		now = now.Add(500 * time.Millisecond)
		got := a.step(now, in, budgetKbps(10000, 0, 0), 10000)
		jumps := 0
		for id, rid := range got {
			if rid != a.cur[id] {
				jumps++
			}
			seen[id+rid] = true
		}
	}
	got := a.cur
	if got["u0"] != "f" || got["u1"] != "f" {
		t.Fatalf("a healthy 10 Mbps link should end at full quality: %v", got)
	}
	if !seen["u0h"] || !seen["u1h"] {
		t.Fatal("quality must pass through h, not leap from q to f")
	}
}

func TestDropsImmediatelyWhenTheEstimateFalls(t *testing.T) {
	now := time.Unix(0, 0)
	a := newAdapter(defaultAdaptCfg())
	in := streams(4)
	run(a, &now, in, 20000, 60*time.Second)
	for _, r := range a.cur {
		if r != "f" {
			t.Fatalf("setup: %v", a.cur)
		}
	}
	// The user walks out of Wi-Fi range: one evaluation later, everyone is lower.
	now = now.Add(500 * time.Millisecond)
	got := a.step(now, in, budgetKbps(900, 0, 0), 900)
	for id, rid := range got {
		if rid == "" {
			t.Fatalf("%s lost its picture on a poor link", id)
		}
		if rid == "f" {
			t.Fatalf("%s still on f at 900 kbps", id)
		}
	}
	if usageKbps(in, got) > 4*150+4*350 {
		t.Fatalf("still using %d kbps", usageKbps(in, got))
	}
	// Collapse: everyone drops to q but nobody disappears.
	now = now.Add(500 * time.Millisecond)
	got = a.step(now, in, budgetKbps(50, 0, 0), 50)
	for id, rid := range got {
		if rid != "q" {
			t.Fatalf("%s on %q at 50 kbps; q is the floor, and nobody may vanish", id, rid)
		}
	}
}

func TestDoesNotFlapOnANoisyLink(t *testing.T) {
	now := time.Unix(0, 0)
	a := newAdapter(defaultAdaptCfg())
	in := streams(3)
	run(a, &now, in, 3000, 30*time.Second)
	changes := 0
	prev := fmt.Sprint(a.cur)
	for i := 0; i < 120; i++ { // a minute alternating between good and bad
		est := 3000
		if i%2 == 0 {
			est = 800
		}
		now = now.Add(500 * time.Millisecond)
		a.step(now, in, budgetKbps(est, 0, 0), est)
		if s := fmt.Sprint(a.cur); s != prev {
			changes++
			prev = s
		}
	}
	if changes > 8 {
		t.Fatalf("%d layer changes in a minute on a flapping link; it should settle low and stay", changes)
	}
}

func TestRecoversAfterTheLinkComesBack(t *testing.T) {
	now := time.Unix(0, 0)
	a := newAdapter(defaultAdaptCfg())
	in := streams(3)
	run(a, &now, in, 20000, 30*time.Second)
	run(a, &now, in, 200, 5*time.Second) // network switch: nearly nothing for a while
	for _, r := range a.cur {
		if r != "q" {
			t.Fatalf("during the outage: %v", a.cur)
		}
	}
	run(a, &now, in, 20000, 60*time.Second)
	for _, r := range a.cur {
		if r != "f" {
			t.Fatalf("a minute after recovery everyone should be back at full quality: %v", a.cur)
		}
	}
}

func TestStuckEstimatorIsProbedByATrialRise(t *testing.T) {
	// The estimator is held down by how little we send (it only grows toward
	// 1.5x what it sees), so the budget alone would pin everyone on q forever.
	// Here the link is really fine: the estimate rises as soon as we send more.
	now := time.Unix(0, 0)
	a := newAdapter(defaultAdaptCfg())
	in := streams(1)
	for i := 0; i < 160; i++ {
		est := 200
		if a.cur["u0"] != "" && a.cur["u0"] != "q" {
			est = 1500
		}
		now = now.Add(500 * time.Millisecond)
		a.step(now, in, budgetKbps(est, 0, 0), est)
	}
	if a.cur["u0"] == "q" {
		t.Fatalf("a link that can carry more was never tried: %v", a.cur)
	}
}

func TestFailedTrialBacksOffInsteadOfRepeating(t *testing.T) {
	now := time.Unix(0, 0)
	a := newAdapter(defaultAdaptCfg())
	in := streams(1)
	run(a, &now, in, 200, 30*time.Second) // trial moves to h
	rises := 0
	prev := a.cur["u0"]
	for i := 0; i < 240; i++ { // the link really is only ~200 kbps: every rise fails
		est := 200
		if a.cur["u0"] != "q" {
			est = 60 // the estimate collapses as soon as we send more than fits
		}
		now = now.Add(500 * time.Millisecond)
		a.step(now, in, budgetKbps(est, 0, 0), est)
		if a.cur["u0"] != prev && rankOf(a.cur["u0"]) > rankOf(prev) {
			rises++
		}
		prev = a.cur["u0"]
	}
	if rises > 4 {
		t.Fatalf("%d failed rises in two minutes; backoff should space them out", rises)
	}
	if a.backoff < 20*time.Second {
		t.Fatalf("backoff %v should have grown after repeated failures", a.backoff)
	}
}

func TestDataSaverCapsTheBudget(t *testing.T) {
	if got := budgetKbps(50000, 600, 0); got != 600 {
		t.Fatalf("cap ignored: %d", got)
	}
	if got := budgetKbps(0, 0, 0); got != unlimited {
		t.Fatalf("no estimator and no cap should not limit: %d", got)
	}
	if got := budgetKbps(1000, 0, 100); got != 750 {
		t.Fatalf("85%% of 1000 less 100 audio: %d", got)
	}
	if got := budgetKbps(10, 0, 100); got != 0 {
		t.Fatalf("never negative: %d", got)
	}
}

func TestHiddenTileStopsAndShowingItStartsAgain(t *testing.T) {
	now := time.Unix(0, 0)
	a := newAdapter(defaultAdaptCfg())
	in := streams(2)
	run(a, &now, in, 20000, 20*time.Second)
	in[1].Hidden = true
	now = now.Add(500 * time.Millisecond)
	if got := a.step(now, in, unlimited, 20000); got["u1"] != "" || got["u0"] == "" {
		t.Fatalf("hiding one tile must stop only that stream: %v", got)
	}
	in[1].Hidden = false
	now = now.Add(500 * time.Millisecond)
	if got := a.step(now, in, unlimited, 20000); got["u1"] != "q" {
		t.Fatalf("a re-shown tile should return on the smallest layer: %v", got)
	}
}

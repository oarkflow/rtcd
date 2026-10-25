package sfu

import (
	"testing"
	"time"
)

func looks(d *speakerDetector, now *time.Time, n int, loud map[string]int) (string, int) {
	changes := 0
	var cur string
	for i := 0; i < n; i++ {
		*now = now.Add(250 * time.Millisecond)
		var ch bool
		cur, ch = d.update(*now, loud)
		if ch {
			changes++
		}
	}
	return cur, changes
}

func TestMeter(t *testing.T) {
	var m meter
	if m.take() != -1 {
		t.Fatal("no packets should read as silence")
	}
	m.add(0x80 | 20) // voice, level 20 dBov: loud
	m.add(20)
	if got := m.take(); got != 107 {
		t.Fatalf("mean loudness %d, want 107", got)
	}
	if m.take() != -1 {
		t.Fatal("take must reset")
	}
}

func TestTheLoudestPersistentVoiceIsTheSpeaker(t *testing.T) {
	d := newSpeakerDetector()
	now := time.Unix(0, 0)
	if cur, _ := looks(d, &now, 8, map[string]int{"ada": 100, "bob": -1, "cy": 40}); cur != "ada" {
		t.Fatalf("speaker %q", cur)
	}
	// Room noise is not speech.
	d = newSpeakerDetector()
	if cur, _ := looks(d, &now, 12, map[string]int{"ada": 55, "bob": 60}); cur != "" {
		t.Fatalf("noise made %q the speaker", cur)
	}
}

func TestSpeakerDoesNotFlapOnInterjections(t *testing.T) {
	d := newSpeakerDetector()
	now := time.Unix(0, 0)
	looks(d, &now, 8, map[string]int{"ada": 100, "bob": -1})
	// Bob coughs for half a second; ada keeps talking.
	if _, ch := looks(d, &now, 2, map[string]int{"ada": 100, "bob": 110}); ch != 0 {
		t.Fatal("a brief interjection took over the highlight")
	}
	if cur, _ := looks(d, &now, 4, map[string]int{"ada": 100, "bob": -1}); cur != "ada" {
		t.Fatalf("speaker %q", cur)
	}
}

func TestSpeakerChangesWhenAnotherTakesOver(t *testing.T) {
	d := newSpeakerDetector()
	now := time.Unix(0, 0)
	looks(d, &now, 8, map[string]int{"ada": 100, "bob": -1})
	cur, changes := looks(d, &now, 16, map[string]int{"ada": -1, "bob": 105})
	if cur != "bob" || changes != 1 {
		t.Fatalf("speaker %q after %d changes; want a single change to bob", cur, changes)
	}
}

func TestSpeakerIsHeldBrieflyThenCleared(t *testing.T) {
	d := newSpeakerDetector()
	now := time.Unix(0, 0)
	looks(d, &now, 8, map[string]int{"ada": 100})
	if cur, _ := looks(d, &now, 3, map[string]int{"ada": -1}); cur != "ada" {
		t.Fatal("dropped the speaker in the middle of a pause")
	}
	if cur, _ := looks(d, &now, 16, map[string]int{"ada": -1}); cur != "" {
		t.Fatalf("still %q long after they went quiet", cur)
	}
}

func TestSpeakerWhoLeavesIsForgotten(t *testing.T) {
	d := newSpeakerDetector()
	now := time.Unix(0, 0)
	looks(d, &now, 8, map[string]int{"ada": 100, "bob": 30})
	if cur, _ := looks(d, &now, 2, map[string]int{"bob": 100}); cur == "ada" {
		t.Fatal("a participant who left is still the speaker")
	}
}

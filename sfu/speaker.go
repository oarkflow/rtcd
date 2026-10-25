package sfu

import (
	"sync/atomic"
	"time"
)

// Active-speaker detection.
//
// Browsers tag each Opus packet with its loudness (RFC 6464, the ssrc-audio-
// level header extension: 0 is as loud as it gets, 127 is silence, in -dBov).
// The server turns that into "who is talking", which it uses to favour that
// person's video when bandwidth is short and tells every participant so the
// page can highlight them. Nothing about this hides anyone: it only changes
// who is raised first.

const audioLevelURI = "urn:ietf:params:rtp-hdrext:ssrc-audio-level"

// meter accumulates the loudness of one participant's packets between looks.
type meter struct {
	sum   atomic.Int64
	count atomic.Int64
}

// add records a packet's level byte (V bit, 7-bit level in -dBov).
func (m *meter) add(levelByte byte) {
	loud := 127 - int64(levelByte&0x7F) // 0 silent .. 127 loud
	m.sum.Add(loud)
	m.count.Add(1)
}

// take returns the mean loudness since the last call and resets, or -1 when no
// audio arrived (a muted or absent microphone).
func (m *meter) take() int {
	n := m.count.Swap(0)
	s := m.sum.Swap(0)
	if n == 0 {
		return -1
	}
	return int(s / n)
}

const (
	// speechLoudness is the mean loudness (127 - level) above which a window
	// counts as speech: a level of -52 dBov or louder. Room noise sits well below.
	speechLoudness = 75
	// minScore is the smoothed score a participant needs to be considered at all.
	minScore = 30
	// holdFor is how long a speaker is kept after falling silent, so a breath
	// between sentences does not make the highlight jump.
	holdFor = 2 * time.Second
	// takeoverWindows is how many consecutive looks (250 ms each) a louder
	// challenger must win before it replaces the current speaker.
	takeoverWindows = 3
)

// speakerDetector picks the dominant speaker of one room from periodic loudness
// readings. It is pure, so its behaviour is tested without any audio.
type speakerDetector struct {
	score      map[string]float64
	current    string
	lastHeard  time.Time
	challenger string
	wins       int
}

func newSpeakerDetector() *speakerDetector { return &speakerDetector{score: map[string]float64{}} }

// update feeds one look at the room: the mean loudness per participant (-1 for
// silence or no audio). It returns the speaker now and whether it changed.
func (d *speakerDetector) update(now time.Time, loud map[string]int) (string, bool) {
	for u := range d.score {
		if _, ok := loud[u]; !ok {
			delete(d.score, u) // left the room
		}
	}
	for u, l := range loud {
		v := 0.0
		if l >= speechLoudness {
			v = float64(l)
		}
		d.score[u] = 0.6*d.score[u] + 0.4*v
	}
	best, bestScore := "", 0.0
	for u, sc := range d.score {
		if sc >= minScore && (sc > bestScore || (sc == bestScore && u < best)) {
			best, bestScore = u, sc
		}
	}
	prev := d.current
	cur := d.current
	if _, here := d.score[cur]; !here {
		cur = ""
	}
	if cur != "" && d.score[cur] >= minScore {
		d.lastHeard = now
	}
	switch {
	case best == "":
		// Nobody is speaking: keep the last speaker for a moment, then none.
		if cur != "" && now.Sub(d.lastHeard) > holdFor {
			cur = ""
		}
		d.challenger, d.wins = "", 0
	case cur == "":
		cur, d.lastHeard = best, now
		d.challenger, d.wins = "", 0
	case best == cur:
		d.challenger, d.wins = "", 0
	default:
		// Someone else is louder. Replace the speaker only if they stay louder
		// for a few looks, or the speaker has gone quiet.
		if d.score[cur] < minScore {
			cur, d.lastHeard = best, now
			d.challenger, d.wins = "", 0
			break
		}
		if d.challenger == best {
			d.wins++
		} else {
			d.challenger, d.wins = best, 1
		}
		if d.wins >= takeoverWindows && bestScore > d.score[cur]*1.25 {
			cur, d.lastHeard = best, now
			d.challenger, d.wins = "", 0
		}
	}
	d.current = cur
	return cur, cur != prev
}

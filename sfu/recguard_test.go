package sfu

import (
	"context"
	"testing"
	"time"
)

func TestRecordingIsRefusedWhenTheDiskIsTooFull(t *testing.T) {
	est := &estimates{}
	est.set("ada", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.RecordDir = t.TempDir(); c.RecordMinFree = 1 << 62 })
	c := h.newClient("ada")
	c.startRealMic()
	c.join(context.Background())
	if _, ok := freeBytes(h.srv.cfg.RecordDir); !ok {
		t.Skip("no free-space query on this platform")
	}
	if _, err := h.srv.StartRecording(testRoom, "ada"); err != ErrDiskFull {
		t.Fatalf("a recording on a full disk: %v", err)
	}
}

func TestARecordingStopsAtItsMaximumDuration(t *testing.T) {
	est := &estimates{}
	est.set("ada", 30000)
	h := newSimHarness(t, est, func(c *Config) { c.RecordDir = t.TempDir(); c.RecordMaxDuration = time.Second })
	c := h.newClient("ada")
	c.startRealMic()
	c.join(context.Background())
	if _, err := h.srv.StartRecording(testRoom, "ada"); err != nil {
		t.Fatal(err)
	}
	// The watcher looks every 10 s; waiting out one tick is cheaper than a hook.
	eventually(t, 25*time.Second, "recording stopped by the limit", func() bool {
		_, on := h.srv.Recording(testRoom)
		return !on
	})
}

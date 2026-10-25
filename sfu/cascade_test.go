package sfu

import (
	"context"
	"testing"
	"time"
)

// twoNodes starts a hub and a leaf for one room. People join each through its
// own harness; the leaf relays to the hub.
func twoNodes(t *testing.T) (hub, leaf *harness, estHub, estLeaf *estimates) {
	t.Helper()
	estHub, estLeaf = &estimates{}, &estimates{}
	hub, leaf = newSimHarness(t, estHub, nil), newSimHarness(t, estLeaf, nil)
	return
}

func openLeaf(t *testing.T, hub, leaf *harness) *Cascade {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := leaf.srv.OpenCascade(ctx, testRoom, "leafB", LocalUpstream{Hub: hub.srv, Room: testRoom, Node: "leafB"})
	if err != nil {
		t.Fatalf("opening the cascade: %v", err)
	}
	return c
}

func TestEveryoneSeesEveryoneAcrossTwoNodes(t *testing.T) {
	ctx := context.Background()
	hub, leaf, estHub, estLeaf := twoNodes(t)
	for _, u := range []string{"ada", "cy"} {
		estHub.set(u, 30000)
	}
	estLeaf.set("bob", 30000)

	ada, cy := hub.newClient("ada"), hub.newClient("cy")
	for _, c := range []*client{ada, cy} {
		c.startCamera("q", "h", "f")
		c.join(ctx)
	}
	openLeaf(t, hub, leaf)
	bob := leaf.newClient("bob")
	bob.startCamera("q", "h", "f")
	bob.join(ctx)

	w := map[string]*watcher{"ada": ada.watch(), "cy": cy.watch(), "bob": bob.watch()}
	for _, viewer := range []string{"ada", "cy", "bob"} {
		for _, pub := range []string{"ada", "cy", "bob"} {
			if viewer == pub {
				continue
			}
			viewer, pub := viewer, pub
			eventually(t, 40*time.Second, viewer+" sees "+pub+" (across nodes where needed)", func() bool {
				r := w[viewer].from(pub)
				return r != nil && r.count() > 30 && time.Since(r.last().at) < time.Second
			})
		}
	}
	// Whoever is relayed keeps their own name; nothing shows a relay.
	for _, viewer := range []string{"ada", "cy", "bob"} {
		w[viewer].mu.Lock()
		for who := range w[viewer].rx {
			if who != "ada" && who != "cy" && who != "bob" {
				t.Fatalf("%s sees a stream named %q", viewer, who)
			}
		}
		w[viewer].mu.Unlock()
	}
	// Relays are not people.
	if got := len(hub.srv.Peers(testRoom)); got != 2 {
		t.Fatalf("the hub lists %d people, want 2 (ada, cy): %v", got, hub.srv.Peers(testRoom))
	}
	if got := hub.srv.Stats(); got.Peers != 2 || got.Rooms != 1 {
		t.Fatalf("hub stats %+v", got)
	}
	if got := leaf.srv.Peers(testRoom); len(got) != 1 || got[0] != "bob" {
		t.Fatalf("the leaf lists %v, want [bob]", got)
	}
	// Each side picks layers for its own viewers: bob, on the leaf, climbs to full
	// quality on ada's video even though ada is on another node.
	eventually(t, 40*time.Second, "bob on full quality of ada, across the link", func() bool { return w["bob"].layerNow("ada") == "f" })
	// ... and a poor link on the leaf lowers only bob's view.
	estLeaf.set("bob", 90)
	eventually(t, 20*time.Second, "bob drops to the smallest layer of ada", func() bool { return w["bob"].layerNow("ada") == "q" })
	if w["cy"].layerNow("ada") != "f" {
		t.Fatalf("cy, on the hub with a good link, was affected by bob's poor link: %s", w["cy"].layerNow("ada"))
	}
	continuous(t, w["bob"].from("ada").all(), "bob watching ada across the relay")
	continuous(t, w["ada"].from("bob").all(), "ada watching bob across the relay")
}

func TestLeavingTheLeafClosesTheRelay(t *testing.T) {
	ctx := context.Background()
	hub, leaf, estHub, estLeaf := twoNodes(t)
	estHub.set("ada", 30000)
	estLeaf.set("bob", 30000)
	ada := hub.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	openLeaf(t, hub, leaf)
	bob := leaf.newClient("bob")
	bob.startCamera("q", "h", "f")
	bob.join(ctx)
	wa, wb := ada.watch(), bob.watch()
	eventually(t, 30*time.Second, "ada sees bob", func() bool { r := wa.from("bob"); return r != nil && r.count() > 30 })
	eventually(t, 30*time.Second, "bob sees ada", func() bool { r := wb.from("ada"); return r != nil && r.count() > 30 })

	leaf.srv.Leave(testRoom, "bob")
	// The hub stops showing bob, and the relay link is torn down with the last
	// person on the leaf: nothing is left running for an empty room.
	eventually(t, 15*time.Second, "bob gone from ada's screen", func() bool {
		st, _ := hub.srv.PeerStats(testRoom, "ada")
		return len(st.Streams) == 0
	})
	eventually(t, 15*time.Second, "the cascade closed", func() bool { return leaf.srv.Cascade(testRoom) == nil })
	eventually(t, 15*time.Second, "the leaf has no room left", func() bool { return leaf.srv.Stats() == Stats{} })
	hub.srv.find(testRoom, "ada").nmu.Lock()
	n := 0
	hub.srv.rooms[testRoom].mu.Lock()
	for _, p := range hub.srv.rooms[testRoom].peers {
		if p.relay {
			n++
		}
	}
	hub.srv.rooms[testRoom].mu.Unlock()
	hub.srv.find(testRoom, "ada").nmu.Unlock()
	if n != 0 {
		t.Fatalf("%d relay connections still on the hub", n)
	}
}

func TestACutRelayConnectionIsRebuiltAndVideoReturns(t *testing.T) {
	ctx := context.Background()
	hub, leaf, estHub, estLeaf := twoNodes(t)
	estHub.set("ada", 30000)
	estLeaf.set("bob", 30000)
	ada := hub.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	c := openLeaf(t, hub, leaf)
	bob := leaf.newClient("bob")
	bob.startCamera("q", "h", "f")
	bob.join(ctx)
	wa, wb := ada.watch(), bob.watch()
	eventually(t, 30*time.Second, "both directions", func() bool {
		a, b := wa.from("bob"), wb.from("ada")
		return a != nil && b != nil && a.count() > 30 && b.count() > 30
	})

	// Break the connection that brings the hub's video to the leaf, and the one
	// that takes the leaf's video to the hub.
	c.mu.Lock()
	down, up := c.downPC, c.upPC
	c.mu.Unlock()
	_ = down.Close()
	_ = up.Close()
	mark := wb.from("ada").count()
	markA := wa.from("bob").count()
	eventually(t, 40*time.Second, "bob sees ada again through a rebuilt link", func() bool {
		r := wb.from("ada")
		return r != nil && r.count() > mark+60 && time.Since(r.last().at) < time.Second
	})
	eventually(t, 40*time.Second, "ada sees bob again", func() bool {
		r := wa.from("bob")
		return r != nil && r.count() > markA+60 && time.Since(r.last().at) < time.Second
	})
	if got := hub.srv.Peers(testRoom); len(got) != 1 || got[0] != "ada" {
		t.Fatalf("the hub's people: %v", got)
	}
}

func TestCodecsAreRelayedWholeAcrossNodes(t *testing.T) {
	ctx := context.Background()
	hub, leaf, estHub, estLeaf := twoNodes(t)
	estHub.set("ada", 30000)
	estHub.set("cy", 30000)
	estLeaf.set("bob", 30000)
	ada, cy := hub.newClient("ada"), hub.newClient("cy")
	ada.startH264Camera("q", "h", "f") // H.264 simulcast on the hub
	cy.startSVCCamera()                // VP9 SVC on the hub
	ada.join(ctx)
	cy.join(ctx)
	openLeaf(t, hub, leaf)
	bob := leaf.newClient("bob")
	bob.startCamera("q", "h", "f") // VP8 simulcast on the leaf
	bob.join(ctx)

	w := map[string]*rawWatcher{"ada": ada.rawWatch(), "bob": bob.rawWatch(), "cy": cy.rawWatch()}
	want := map[string]string{"ada": "video/H264", "bob": "video/VP8", "cy": "video/VP9"}
	for _, viewer := range []string{"ada", "bob", "cy"} {
		for pub, mime := range want {
			if viewer == pub {
				continue
			}
			viewer, pub, mime := viewer, pub, mime
			eventually(t, 40*time.Second, viewer+" receives "+pub+"'s "+mime+" across nodes", func() bool { return w[viewer].n(pub) > 30 })
			if got := w[viewer].mime(pub); got != mime {
				t.Fatalf("%s receives %s as %s, want %s", viewer, pub, got, mime)
			}
		}
	}
}

func TestLeafParticipantsJoiningAndLeavingRepeatedly(t *testing.T) {
	ctx := context.Background()
	hub, leaf, estHub, estLeaf := twoNodes(t)
	estHub.set("ada", 30000)
	estLeaf.set("bob", 30000)
	ada := hub.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.join(ctx)
	wa := ada.watch()
	openLeaf(t, hub, leaf)
	for round := 0; round < 4; round++ {
		bob := leaf.newClient("bob")
		bob.startCamera("q", "h", "f")
		bob.join(ctx)
		wb := bob.watch()
		eventually(t, 30*time.Second, "ada sees bob this round", func() bool {
			r := wa.from("bob")
			return r != nil && time.Since(r.last().at) < time.Second
		})
		eventually(t, 30*time.Second, "bob sees ada this round", func() bool {
			r := wb.from("ada")
			return r != nil && r.count() > 20 && time.Since(r.last().at) < time.Second
		})
		leaf.srv.Leave(testRoom, "bob")
		eventually(t, 15*time.Second, "bob removed from ada's screen", func() bool {
			st, _ := hub.srv.PeerStats(testRoom, "ada")
			return len(st.Streams) == 0
		})
		wa.mu.Lock()
		delete(wa.rx, "bob")
		wa.mu.Unlock()
		eventually(t, 15*time.Second, "the cascade closes between rounds", func() bool { return leaf.srv.Cascade(testRoom) == nil })
		if round < 3 {
			openLeaf(t, hub, leaf)
		}
	}
}

func TestAnEncryptedRoomStaysEncryptedAcrossNodes(t *testing.T) {
	ctx := context.Background()
	estHub, estLeaf := &estimates{}, &estimates{}
	hub := newSimHarness(t, estHub, func(c *Config) { c.RecordDir = t.TempDir() })
	leaf := newSimHarness(t, estLeaf, nil)
	estHub.set("ada", 30000)
	estLeaf.set("bob", 30000)
	// The relay reaches the hub before anybody local: it must still mark the room.
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	bob := leaf.newClient("bob")
	bob.startCamera("q", "h", "f")
	bob.secureJoin(ctx)
	if _, err := leaf.srv.OpenCascade(cctx, testRoom, "leafB", LocalUpstream{Hub: hub.srv, Room: testRoom, Node: "leafB", Secure: true}); err != nil {
		t.Fatal(err)
	}
	if !hub.srv.E2EE(testRoom) {
		t.Fatal("the hub's room is not marked encrypted by the relay")
	}
	mallory := hub.newClient("mallory")
	if _, err := hub.srv.Join(ctx, testRoom, "mallory", offerOf(t, mallory)); err != ErrE2EERequired {
		t.Fatalf("a plain join to the hub's encrypted room: %v", err)
	}
	ada := hub.newClient("ada")
	ada.startCamera("q", "h", "f")
	ada.secureJoin(ctx)
	wa, wb := ada.watch(), bob.watch()
	eventually(t, 40*time.Second, "ada sees bob across the link", func() bool { r := wa.from("bob"); return r != nil && r.count() > 30 })
	eventually(t, 40*time.Second, "bob sees ada across the link", func() bool { r := wb.from("ada"); return r != nil && r.count() > 30 })
	if _, err := hub.srv.StartRecording(testRoom, "ada"); err != ErrRecordingE2EE {
		t.Fatalf("recording the hub's encrypted room: %v", err)
	}
}

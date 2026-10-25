package server

import (
	"encoding/json"
	"strings"

	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/calls"
	"github.com/oarkflow/rtcd/sfu"
	"github.com/pion/webrtc/v4"
)

// room checks that the caller is a joined participant of a live group call of
// their own tenant, from memory, and returns what the operation needs.
func (s *Server) room(o *opCtx, id string) (calls.View, error) {
	o.target = id
	v, err := s.Store.Peek(o, o.actor(), id)
	switch {
	case err != nil:
		return v, err
	case v.Mode != calls.SFU:
		return v, bad("this is not a group call")
	case v.Status == calls.Ended:
		return v, &apiError{410, "call_ended", ""}
	case v.State != "joined":
		return v, conflict("answer_the_call_first")
	}
	s.tenants.Store(v.ID, v.Tenant)
	return v, nil
}

type sdpBody struct {
	Call string `json:"call"`
	SDP  string `json:"sdp"`
	E2EE bool   `json:"e2ee"`
}

func sdp(raw json.RawMessage) (sdpBody, error) {
	in, err := decode[sdpBody](raw)
	if err != nil {
		return in, err
	}
	if in.SDP == "" {
		return in, bad("sdp is required")
	}
	in.SDP = strings.Clone(in.SDP) // Pion keeps substrings of what it is given
	return in, nil
}

func (s *Server) registerSFU() {
	sf := func(name string, quiet bool, run func(o *opCtx, v calls.View, raw json.RawMessage) (any, error)) {
		s.register(opDef{name: "sfu." + name, scope: auth.ScopeCalls, quiet: quiet, run: func(o *opCtx, raw json.RawMessage) (any, error) {
			in, err := decode[callRef](raw)
			if err != nil {
				return nil, err
			}
			v, err := s.room(o, in.Call)
			if err != nil {
				return nil, err
			}
			return run(o, v, raw)
		}})
	}
	sf("join", false, func(o *opCtx, v calls.View, raw json.RawMessage) (any, error) {
		in, err := sdp(raw)
		if err != nil {
			return nil, err
		}
		o.note("e2ee", v.E2EE)
		offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: in.SDP}
		var ans webrtc.SessionDescription
		if v.E2EE {
			// The service cannot check that media is encrypted, but it can refuse
			// a client that does not even claim to, and it never lets one into the
			// room of an encrypted call.
			if !in.E2EE {
				return nil, sfu.ErrE2EERequired
			}
			ans, err = s.SFU.JoinSecure(o, v.ID, o.sess.who.ID, offer)
		} else {
			ans, err = s.SFU.Join(o, v.ID, o.sess.who.ID, offer)
		}
		if err != nil {
			return nil, err
		}
		// peers is who is in the room now, so a newcomer need not wait for events.
		return map[string]any{"type": "answer", "sdp": ans.SDP, "e2ee": v.E2EE, "peers": s.SFU.Peers(v.ID)}, nil
	})
	sf("answer", false, func(o *opCtx, v calls.View, raw json.RawMessage) (any, error) {
		in, err := sdp(raw)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, s.SFU.Answer(v.ID, o.sess.who.ID, webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: in.SDP})
	})
	sf("candidate", true, func(o *opCtx, v calls.View, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Call string `json:"call"`
			webrtc.ICECandidateInit
		}](raw)
		if err != nil || in.Candidate == "" {
			return nil, bad("candidate is required")
		}
		c := in.ICECandidateInit
		c.Candidate = strings.Clone(c.Candidate)
		return map[string]any{"ok": true}, s.SFU.Candidate(v.ID, o.sess.who.ID, c)
	})
	// ready is sent once the join answer has been applied; the server holds its
	// first offer until then.
	sf("ready", true, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		return map[string]any{"ok": true}, s.SFU.Ready(v.ID, o.sess.who.ID)
	})
	// restart moves an existing connection to a new network path: the client
	// sends an offer made with iceRestart and gets an answer. Its tracks, and
	// everyone's subscriptions to them, are untouched.
	sf("restart", false, func(o *opCtx, v calls.View, raw json.RawMessage) (any, error) {
		in, err := sdp(raw)
		if err != nil {
			return nil, err
		}
		ans, err := s.SFU.Restart(o, v.ID, o.sess.who.ID, webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: in.SDP})
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "answer", "sdp": ans.SDP}, nil
	})
	// resync asks for the outstanding server offer again, after the client's
	// connection was down.
	sf("resync", true, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		return map[string]any{"ok": true}, s.SFU.Resync(v.ID, o.sess.who.ID)
	})
	// prefs sets how this participant wants everyone's video: tile sizes, hidden
	// tiles, a pinned speaker, a data-saver ceiling.
	sf("prefs", true, func(o *opCtx, v calls.View, raw json.RawMessage) (any, error) {
		in, err := decode[sfu.Prefs](raw)
		if err != nil {
			return nil, sfu.ErrBadPrefs
		}
		return map[string]any{"ok": true}, s.SFU.Prefer(v.ID, o.sess.who.ID, in)
	})
	sf("stats", true, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		return s.SFU.PeerStats(v.ID, o.sess.who.ID)
	})
	// sample shows the caller the start of their own recent media as the service
	// holds it. In an encrypted call that is ciphertext: a way to check, with
	// your own eyes, that the service cannot read what you send.
	sf("sample", false, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		got, err := s.SFU.Sample(v.ID, o.sess.who.ID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"e2ee": s.SFU.E2EE(v.ID), "sample": got}, nil
	})
	// Recording is the caller's alone to start and stop; everyone is told.
	sf("record.start", false, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		if o.sess.who.ID != v.Initiator {
			return nil, denied("only_the_caller_can_record")
		}
		return s.SFU.StartRecording(v.ID, o.sess.who.ID)
	})
	sf("record.stop", false, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		if o.sess.who.ID != v.Initiator {
			return nil, denied("only_the_caller_can_record")
		}
		return s.SFU.StopRecording(v.ID, o.sess.who.ID)
	})
	sf("record.status", true, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		info, on := s.SFU.Recording(v.ID)
		return map[string]any{"recording": on, "started_by": info.StartedBy, "started_at": info.StartedAt}, nil
	})
	sf("leave", false, func(o *opCtx, v calls.View, _ json.RawMessage) (any, error) {
		s.SFU.Leave(v.ID, o.sess.who.ID)
		return map[string]any{"ok": true}, nil
	})
}

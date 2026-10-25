package server

import (
	"encoding/json"

	"github.com/oarkflow/rtcd/calls"
	"github.com/oarkflow/rtcd/sfu"
)

// Managed rooms are for a backend that already knows who may be in a call. The
// backend opens a room under its own id, says who is admitted, and changes that
// as its own membership changes; its users then connect with tokens it minted
// and go straight to sfu.join. There is no ringing, and the backend, not any
// participant, decides when the room ends. See calls.OpenRoom.

type roomBody struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	E2EE    *bool    `json:"e2ee"`
	Members []string `json:"members"`
	// Policy
	MaxPeers   int `json:"max_peers"`
	LastNVideo int `json:"last_n_video"`
	LastNAudio int `json:"last_n_audio"`
}

func (s *Server) registerRooms() {
	s.register(opDef{name: "room.open", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[roomBody](raw)
		if err != nil {
			return nil, err
		}
		if err := validUsers(in.Members); err != nil {
			return nil, err
		}
		if in.MaxPeers < 0 || in.LastNVideo < 0 || in.LastNAudio < 0 {
			return nil, bad("limits cannot be negative")
		}
		o.target = in.ID
		o.note("members", len(in.Members))
		c, err := s.Store.OpenRoom(o, o.sess.who.Tenant, calls.RoomOptions{ID: in.ID, Kind: in.Kind, E2EE: in.E2EE, Members: in.Members})
		if err != nil {
			return nil, err
		}
		s.tenants.Store(c.ID, c.Tenant)
		if in.MaxPeers > 0 || in.LastNVideo > 0 || in.LastNAudio > 0 {
			s.SFU.SetPolicy(c.ID, sfu.Policy{MaxPeers: in.MaxPeers, LastNVideo: in.LastNVideo, LastNAudio: in.LastNAudio})
		}
		o.note("e2ee", c.E2EE)
		return map[string]any{"call": c, "ice_ttl": int(s.cfg.TURNTTL.Seconds())}, nil
	}})
	// room.admit lets more people in (or back in). Admission is the only thing a
	// participant needs before sfu.join.
	s.register(opDef{name: "room.admit", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[roomBody](raw)
		if err != nil {
			return nil, err
		}
		if err := validUsers(in.Members); err != nil {
			return nil, err
		}
		o.target = in.ID
		o.note("members", len(in.Members))
		c, err := s.Store.Admit(o, o.sess.who.Tenant, in.ID, in.Members)
		if err != nil {
			return nil, err
		}
		return map[string]any{"call": c}, nil
	}})
	// room.remove takes people out and disconnects them from the SFU at once.
	s.register(opDef{name: "room.remove", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[roomBody](raw)
		if err != nil {
			return nil, err
		}
		if err := validUsers(in.Members); err != nil {
			return nil, err
		}
		o.target = in.ID
		o.note("members", len(in.Members))
		c, err := s.Store.Remove(o, o.sess.who.Tenant, in.ID, in.Members)
		if err != nil {
			return nil, err
		}
		for _, u := range in.Members {
			s.SFU.Leave(c.ID, u)
			_ = s.Notify(o, c.Tenant, u, "room.removed", mustJSON(map[string]any{"call_id": c.ID}), "")
		}
		return map[string]any{"call": c}, nil
	}})
	s.register(opDef{name: "room.close", service: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[roomBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.ID
		c, err := s.Store.CloseRoom(o, o.sess.who.Tenant, in.ID, "ended")
		if err != nil {
			return nil, err
		}
		s.left(c, "")
		s.SFU.ForgetPolicy(c.ID)
		return map[string]any{"call": c}, nil
	}})
	// room.get tells the backend who is admitted and who is connected to media.
	s.register(opDef{name: "room.get", service: true, quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[roomBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.ID
		c, err := s.Store.RoomView(o, o.sess.who.Tenant, in.ID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"call": c, "connected": s.SFU.Peers(c.ID)}, nil
	}})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

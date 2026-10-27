package server

import (
	"context"
	"encoding/json"

	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/chat"
)

// Device keys and conversation key epochs. See package chat (keys.go) for the
// model: the service is a directory and a mailbox for wrapped keys, and holds
// no key of its own.

const epochBody = 1 << 20 // a rotation carries a wrap for every device of every member

type wrapsBody struct {
	Conv   string      `json:"conv"`
	Device string      `json:"device"`
	Epoch  int64       `json:"epoch"`
	Wraps  []chat.Wrap `json:"wraps"`
}

func (s *Server) registerKeys() {
	reg := func(name string, d opDef) {
		d.name, d.scope = name, auth.ScopeChat
		s.register(d)
	}

	// key.publish {device, pub, cert}: a device announces its public key. cert is
	// opaque to the service; the application puts in it whatever lets members
	// check the key belongs to the person (a signature by their identity key).
	reg("key.publish", opDef{run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Device string `json:"device"`
			Pub    string `json:"pub"`
			Cert   string `json:"cert"`
		}](raw)
		if err != nil {
			return nil, err
		}
		tenant, me := o.sess.who.Tenant, o.sess.who.ID
		o.target = in.Device
		d, created, err := s.Chat.PublishDevice(o, tenant, me, in.Device, in.Pub, in.Cert, s.cfg.MaxDevices)
		if err != nil {
			return nil, err
		}
		o.note("created", created)
		if created {
			go s.announceDevice("key.added", tenant, me, in.Device)
		}
		return map[string]any{"device": d, "created": created}, nil
	}})

	// key.revoke {device}: retires one of the caller's devices (a backend names
	// the user in X-RTC-User). Conversations that use epochs then need a new one,
	// since that device held their keys.
	reg("key.revoke", opDef{run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Device string `json:"device"`
		}](raw)
		if err != nil {
			return nil, err
		}
		tenant, me := o.sess.who.Tenant, o.sess.who.ID
		o.target = in.Device
		changed, err := s.Chat.RevokeDevice(o, tenant, me, in.Device)
		if err != nil {
			return nil, err
		}
		if changed {
			go s.deviceRevoked(tenant, me, in.Device)
		}
		return map[string]any{"revoked": changed}, nil
	}})

	// key.list {conv}: the active device keys of everyone in a conversation.
	reg("key.list", opDef{quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv string `json:"conv"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		devs, err := s.Chat.Devices(o, o.sess.who.Tenant, ci.members)
		if devs == nil {
			devs = []chat.Device{}
		}
		return map[string]any{"devices": devs}, err
	}})

	// epoch.get {conv, device, since}: the conversation's epoch, whether a new
	// one is required, and the wraps of keys made for this device after `since`.
	reg("epoch.get", opDef{quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[wrapsBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		if _, err := s.conv(o, in.Conv); err != nil {
			return nil, err
		}
		if !chat.ValidDeviceID(in.Device) {
			return nil, bad("device is required")
		}
		tenant := o.sess.who.Tenant
		st, err := s.Chat.Fresh(o, tenant, in.Conv)
		if err != nil {
			return nil, err
		}
		w, err := s.Chat.MyWraps(o, tenant, in.Conv, o.sess.who.ID, in.Device, in.Epoch)
		if w == nil {
			w = []chat.WrapOut{}
		}
		return map[string]any{"epoch": st.Epoch, "rekey_required": st.Rekey, "wraps": w}, err
	}})

	// epoch.missing {conv}: devices of members that hold no wrap of the current
	// epoch, which a member who has the key should grant it to.
	reg("epoch.missing", opDef{quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[wrapsBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		epoch, devs, err := s.Chat.Missing(o, o.sess.who.Tenant, in.Conv, ci.members)
		if devs == nil {
			devs = []chat.Device{}
		}
		return map[string]any{"epoch": epoch, "devices": devs}, err
	}})

	// epoch.rotate {conv, device, epoch, wraps}: starts the next epoch. epoch must
	// be the current one plus one, and wraps must cover every current member
	// (and only devices of current members). A person who left, or a revoked
	// device, cannot be in it.
	reg("epoch.rotate", opDef{maxBody: epochBody, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[wrapsBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		tenant, me := o.sess.who.Tenant, o.sess.who.ID
		o.note("epoch", in.Epoch)
		o.note("wraps", len(in.Wraps))
		if err := s.Chat.Rotate(o, tenant, in.Conv, in.Epoch, me, in.Device, in.Wraps, ci.members); err != nil {
			return nil, err
		}
		raw, _ = jsonMarshal(map[string]any{"conv": in.Conv, "epoch": in.Epoch, "by": me})
		for _, u := range ci.members {
			_ = s.Notify(context.Background(), tenant, u, "epoch.new", raw, me)
		}
		return map[string]any{"epoch": in.Epoch}, nil
	}})

	// epoch.grant {conv, device, epoch, wraps}: gives devices that joined later
	// (a new member, a new device) the key of an epoch that already exists.
	reg("epoch.grant", opDef{maxBody: epochBody, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[wrapsBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		tenant, me := o.sess.who.Tenant, o.sess.who.ID
		o.note("epoch", in.Epoch)
		o.note("wraps", len(in.Wraps))
		n, err := s.Chat.Grant(o, tenant, in.Conv, in.Epoch, me, in.Device, in.Wraps, ci.members)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			seen := map[string]bool{}
			raw, _ = jsonMarshal(map[string]any{"conv": in.Conv, "epoch": in.Epoch})
			for _, w := range in.Wraps {
				if !seen[w.User] {
					seen[w.User] = true
					_ = s.Notify(context.Background(), tenant, w.User, "epoch.granted", raw, me)
				}
			}
		}
		return map[string]any{"added": n}, nil
	}})
}

// peersOf returns the people who share a conversation that uses epochs with
// user: the ones who must hear that a device was added or revoked.
func (s *Server) peersOf(ctx context.Context, tenant, user string) ([]string, []string) {
	convs, err := s.Groups.ConvsOf(ctx, tenant, user)
	if err != nil || len(convs) == 0 {
		return nil, nil
	}
	enc, err := s.Chat.WithEpochs(ctx, tenant, convs)
	if err != nil {
		return nil, nil
	}
	seen := map[string]bool{user: true}
	var out []string
	for i, c := range enc {
		if i >= 200 {
			break
		}
		list, err := s.Groups.Roster(ctx, tenant, c)
		if err != nil {
			continue
		}
		for _, m := range list {
			if !seen[m.User] {
				seen[m.User] = true
				out = append(out, m.User)
			}
		}
	}
	return out, enc
}

func (s *Server) announceDevice(event, tenant, user, device string) {
	ctx, cancel := contextWithTimeout(context.Background(), 20e9)
	defer cancel()
	peers, _ := s.peersOf(ctx, tenant, user)
	raw, _ := jsonMarshal(map[string]any{"user": user, "device": device})
	for _, p := range append(peers, user) { // the user's other devices too
		_ = s.Notify(ctx, tenant, p, event, raw, user)
	}
	s.hook.emit(HookEvent{Type: event, Tenant: tenant, User: user, Device: device})
}

// deviceRevoked makes the conversations the device could read need a new epoch.
func (s *Server) deviceRevoked(tenant, user, device string) {
	ctx, cancel := contextWithTimeout(context.Background(), 20e9)
	defer cancel()
	peers, enc := s.peersOf(ctx, tenant, user)
	flagged, _ := s.Chat.NeedRekey(ctx, tenant, enc)
	raw, _ := jsonMarshal(map[string]any{"user": user, "device": device})
	for _, p := range append(peers, user) {
		_ = s.Notify(ctx, tenant, p, "key.revoked", raw, "")
	}
	s.hook.emit(HookEvent{Type: "key.revoked", Tenant: tenant, User: user, Device: device})
	for _, c := range flagged {
		s.announceRekey(ctx, tenant, c)
	}
}

// announceRekey tells a conversation's members a new epoch is required.
func (s *Server) announceRekey(ctx context.Context, tenant, conv string) {
	list, err := s.Groups.Roster(ctx, tenant, conv)
	if err != nil {
		return
	}
	raw, _ := jsonMarshal(map[string]any{"conv": conv})
	users := make([]string, len(list))
	for i, m := range list {
		users[i] = m.User
		_ = s.Notify(ctx, tenant, m.User, "conv.rekey", raw, "")
	}
	s.hook.emit(HookEvent{Type: "conv.rekey", Tenant: tenant, Conv: conv, Recipients: users})
}

// afterRemove runs when people have left or been taken out of a conversation:
// they lose their wrapped keys, and what they could read is rekeyed.
func (s *Server) afterRemove(ctx context.Context, tenant, id string, users []string) {
	s.dropConvs()
	_ = s.Chat.DropWraps(ctx, tenant, id, users)
	if flagged, _ := s.Chat.NeedRekey(ctx, tenant, []string{id}); len(flagged) > 0 {
		s.announceRekey(ctx, tenant, id)
	}
}

// afterDelete removes everything kept for a conversation that no longer exists.
func (s *Server) afterDelete(ctx context.Context, tenant, id string) {
	s.dropConvs()
	files, _ := s.Chat.PurgeConv(ctx, tenant, id)
	for _, f := range files {
		s.removeFile(tenant, f)
	}
}

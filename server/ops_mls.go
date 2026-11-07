package server

import (
	"context"
	"encoding/json"

	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/chat"
)

// MLS (RFC 9420) delivery. See package chat (mls.go) for the model: the service
// is a KeyPackage directory and an ordered, atomic mailbox of handshake
// messages, and holds no group secret. Application messages are the ordinary
// msg.send, sealed under the group's current epoch.

// A commit that adds a hundred people carries a hundred welcomes.
const mlsCommitBody = 10 << 20

// inlineMax is the largest commit pushed inside the mls.commit event itself.
// A member who gets one applies it without a round trip, which is every member
// in the usual case, and the rare one that is larger (a commit that adds many
// people) fetches it with mls.sync.
const inlineMax = 16 << 10

type mlsBody struct {
	Conv      string         `json:"conv"`
	Device    string         `json:"device"`
	Epoch     int64          `json:"epoch"`
	ID        string         `json:"id"`
	Body      string         `json:"body"`
	Welcomes  []chat.Welcome `json:"welcomes"`
	GroupInfo string         `json:"group_info"`
	Removed   []string       `json:"removed"`
}

func (s *Server) registerMLS() {
	reg := func(name string, d opDef) {
		d.name, d.scope = name, auth.ScopeChat
		s.register(d)
	}

	// mls.kp.put {device, kps}: a device publishes KeyPackages. Each is
	// {kp, last_resort?, ttl?}. Publish one last-resort package, and keep the
	// single-use ones topped up (mls.kp.count says how many are left).
	reg("mls.kp.put", opDef{maxBody: 1 << 20, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Device string      `json:"device"`
			KPs    []chat.KPIn `json:"kps"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Device
		o.note("count", len(in.KPs))
		n, err := s.Chat.PutKeyPackages(o, o.sess.who.Tenant, o.sess.who.ID, in.Device, in.KPs)
		if err != nil {
			return nil, err
		}
		return map[string]any{"added": n}, nil
	}})

	// mls.kp.count {device}: how many single-use packages remain.
	reg("mls.kp.count", opDef{quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Device string `json:"device"`
		}](raw)
		if err != nil {
			return nil, err
		}
		if !chat.ValidDeviceID(in.Device) {
			return nil, bad("device is required")
		}
		n, lr, err := s.Chat.KeyPackageCount(o, o.sess.who.Tenant, o.sess.who.ID, in.Device)
		return map[string]any{"available": n, "last_resort": lr}, err
	}})

	// mls.kp.claim {conv, users}: one KeyPackage per active device of each named
	// user, to add them to the group. The users must be in the conversation's
	// roster (add them to the group first), and the caller must be too, so a
	// stranger cannot use up someone's packages. Single-use packages are
	// consumed; a device with none left yields its last-resort package.
	reg("mls.kp.claim", opDef{run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv  string   `json:"conv"`
			Users []string `json:"users"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		for _, u := range in.Users {
			if !ci.member[u] {
				return nil, bad(u + " is not in this conversation")
			}
		}
		o.note("users", len(in.Users))
		got, missing, err := s.Chat.ClaimKeyPackages(o, o.sess.who.Tenant, in.Users)
		if got == nil {
			got = []chat.Claimed{}
		}
		if missing == nil {
			missing = []string{}
		}
		return map[string]any{"key_packages": got, "missing": missing}, err
	}})

	// mls.group.create {conv, group_id, suite, group_info?}: binds the
	// conversation to an MLS group the caller has just made at epoch 0.
	reg("mls.group.create", opDef{maxBody: 2 << 20, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv      string `json:"conv"`
			GroupID   string `json:"group_id"`
			Suite     int    `json:"suite"`
			GroupInfo string `json:"group_info"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		if _, err := s.conv(o, in.Conv); err != nil {
			return nil, err
		}
		o.note("suite", in.Suite)
		g, err := s.Chat.CreateMLSGroup(o, o.sess.who.Tenant, in.Conv, in.GroupID, in.Suite, in.GroupInfo)
		if err != nil {
			return nil, err
		}
		s.dropConvs()
		return g, nil
	}})

	// mls.group.get {conv}: the group id and suite, the epoch, whether a commit
	// is required first, and the newest GroupInfo.
	reg("mls.group.get", opDef{quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv string `json:"conv"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		if _, err := s.conv(o, in.Conv); err != nil {
			return nil, err
		}
		return s.Chat.MLSGroup(o, o.sess.who.Tenant, in.Conv)
	}})

	// mls.commit {conv, device, epoch, id, body, welcomes, group_info, removed}:
	// publishes a commit that creates `epoch` (the current epoch plus one) and
	// the welcomes for the devices it adds, as one step. If another commit got
	// there first the answer is mls_epoch_conflict with the current epoch: apply
	// what was stored and build the commit again. A retry with the same id after
	// a lost answer returns the commit already stored.
	reg("mls.commit", opDef{maxBody: mlsCommitBody, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[mlsBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		tenant, me := o.sess.who.Tenant, o.sess.who.ID
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		o.note("epoch", in.Epoch)
		o.note("welcomes", len(in.Welcomes))
		out, err := s.Chat.Commit(o, chat.CommitIn{Tenant: tenant, Conv: in.Conv, By: me, ByDevice: in.Device, Epoch: in.Epoch, ID: in.ID,
			Body: in.Body, Welcomes: in.Welcomes, GroupInfo: in.GroupInfo, Removed: in.Removed}, ci.members)
		if err != nil {
			return nil, err
		}
		if !out.Duplicate {
			ev := map[string]any{"conv": in.Conv, "epoch": out.Epoch, "seq": out.Seq, "by": me, "by_device": in.Device, "id": in.ID}
			if len(in.Body) <= inlineMax {
				ev["body"] = in.Body
			}
			if out.Rekey {
				ev["rekey_required"] = true
			}
			evRaw, _ := jsonMarshal(ev)
			for _, u := range ci.members {
				_ = s.Notify(context.Background(), tenant, u, "mls.commit", evRaw, me)
			}
			if len(out.Welcomed) > 0 {
				wRaw, _ := jsonMarshal(map[string]any{"conv": in.Conv, "epoch": out.Epoch})
				seen := map[string]bool{}
				for _, u := range out.Welcomed {
					if !seen[u] {
						seen[u] = true
						_ = s.Notify(context.Background(), tenant, u, "mls.welcome", wRaw, me)
					}
				}
			}
			if s.hook.enabled() {
				s.hook.emit(HookEvent{Type: "mls.commit", Tenant: tenant, Conv: in.Conv, Seq: out.Seq, Sender: me, Epoch: out.Epoch, Recipients: without(ci.members, me)})
			}
		}
		return out, nil
	}})

	// mls.propose {conv, device, epoch, id, body}: a proposal for the current
	// epoch. It does not move the epoch; a committer picks it up.
	reg("mls.propose", opDef{maxBody: 512 << 10, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[mlsBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		tenant, me := o.sess.who.Tenant, o.sess.who.ID
		ci, err := s.conv(o, in.Conv)
		if err != nil {
			return nil, err
		}
		seq, err := s.Chat.Propose(o, tenant, in.Conv, me, in.Device, in.ID, in.Epoch, in.Body)
		if err != nil {
			return nil, err
		}
		evRaw, _ := jsonMarshal(map[string]any{"conv": in.Conv, "epoch": in.Epoch, "seq": seq, "by": me, "kind": chat.KindProposal})
		for _, u := range ci.members {
			_ = s.Notify(context.Background(), tenant, u, "mls.proposal", evRaw, me)
		}
		return map[string]any{"seq": seq}, nil
	}})

	// mls.sync {conv, device, after, limit}: the handshake messages after `after`,
	// in the order every member applies them, with the welcomes made for this
	// device. more is set when the page was full.
	reg("mls.sync", opDef{quiet: true, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv   string `json:"conv"`
			Device string `json:"device"`
			After  int64  `json:"after"`
			Limit  int    `json:"limit"`
		}](raw)
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
		list, more, err := s.Chat.Sync(o, tenant, in.Conv, o.sess.who.ID, in.Device, in.After, in.Limit)
		if err != nil {
			return nil, err
		}
		if list == nil {
			list = []chat.Handshake{}
		}
		st, err := s.Chat.Fresh(o, tenant, in.Conv)
		if err != nil {
			return nil, err
		}
		return map[string]any{"messages": list, "more": more, "epoch": st.Epoch, "rekey_required": st.Rekey}, nil
	}})

	// mls.groupinfo.put {conv, epoch, group_info}: refreshes the stored GroupInfo
	// for the current epoch (for example after the tree changed without a commit
	// of the caller's). A rejoining device reads it with mls.group.get.
	reg("mls.groupinfo.put", opDef{maxBody: 2 << 20, run: func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[mlsBody](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		if _, err := s.conv(o, in.Conv); err != nil {
			return nil, err
		}
		if err := s.Chat.PutGroupInfo(o, o.sess.who.Tenant, in.Conv, in.Epoch, in.GroupInfo); err != nil {
			return nil, err
		}
		return map[string]any{"epoch": in.Epoch}, nil
	}})
}

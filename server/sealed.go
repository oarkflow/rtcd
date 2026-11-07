package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/chat"
)

// POST /v1/sealed/send: a message the service cannot attribute to a member.
//
// There is no sign-in. The caller names the tenant and conversation and
// presents the group send token (see chat.SealedOK): a secret every member of
// the MLS group derives for the epoch and the service has only the hash of.
// The message is stored with no sender and every member is told. The service
// learns that someone in the group spoke; who it was is inside the MLS message,
// authenticated to the members.
//
// What this does not hide: the sender's network address (use a proxy or relay
// for that), and the roster, which the service holds anyway.
//
// Everything that can go wrong answers the same 403 "forbidden": a conversation
// that does not exist, one that is not MLS, a wrong epoch and a wrong token are
// indistinguishable, so the endpoint cannot be used to find conversations or
// guess tokens one question at a time. Guessing a 256-bit token is not the
// threat; the rate limit keeps it from being a load.

const sealedBodyMax = 96 << 10

type sealedIn struct {
	Tenant string `json:"tenant"`
	Conv   string `json:"conv"`
	ID     string `json:"id"`
	Body   string `json:"body"`
	Epoch  int64  `json:"epoch"`
	Token  string `json:"token"`
	TTL    int64  `json:"ttl"`
}

func (s *Server) mountSealed(app *fh.App) {
	app.Post("/v1/sealed/send", s.cors(s.sealedSend))
	app.Options("/v1/sealed/send", s.preflight)
}

func (s *Server) sealedSend(c fh.Ctx) error {
	ip := strings.Clone(c.IP())
	now := s.cfg.Now()
	// Per address first, before any work: this endpoint is open to the world.
	if !s.sealedIP.allow(ip, now) {
		return writeError(c, &apiError{429, "rate_limited", ""})
	}
	if !s.cfg.InsecureHTTP && !transportIsSecure(c) {
		return writeError(c, &apiError{426, "tls_required", ""})
	}
	raw := append([]byte(nil), c.Body()...)
	if len(raw) > sealedBodyMax {
		return writeError(c, &apiError{413, "too_large", ""})
	}
	var in sealedIn
	if err := json.Unmarshal(raw, &in); err != nil {
		return writeError(c, bad("the request is not valid JSON of the expected shape"))
	}
	forbidden := func() error {
		s.auditAnon("sealed.send", "forbidden", ip, "http")
		return writeError(c, denied("forbidden"))
	}
	token, err := base64.RawURLEncoding.DecodeString(in.Token)
	maxBody := s.cfg.MaxMessageBytes
	if maxBody <= 0 {
		maxBody = 32 << 10
	}
	if err != nil || len(token) != 32 || in.Tenant == "" || in.Conv == "" || in.ID == "" || len(in.ID) > 64 || in.Body == "" || len(in.Body) > maxBody {
		return forbidden()
	}
	ctx, cancel := context.WithTimeout(c.Context(), 20*time.Second)
	defer cancel()
	st, ok, err := s.Chat.SealedOK(ctx, in.Tenant, in.Conv, in.Epoch, token)
	if err != nil {
		return writeError(c, err)
	}
	if !ok {
		return forbidden()
	}
	if st.Rekey {
		// Someone was taken out of the roster and no commit has removed them: the
		// same fence as msg.send.
		return writeError(c, &apiError{409, "rekey_required", ""})
	}
	if !s.convLimit.allow(in.Tenant+"\x00"+in.Conv, now) {
		return writeError(c, &apiError{429, "rate_limited", "this conversation is receiving messages faster than its members can be sent them"})
	}
	if in.TTL < 0 || in.TTL > int64(chat.MaxTTL/time.Second) {
		return writeError(c, bad("ttl is 0 to 366 days, in seconds"))
	}
	ttl := time.Duration(in.TTL) * time.Second
	if ttl == 0 {
		ttl = st.TTL
	}
	m, dup, err := s.Chat.Send(ctx, chat.SendIn{Tenant: in.Tenant, Conv: in.Conv, Sender: chat.SealedSender, ID: in.ID, Body: in.Body, Epoch: in.Epoch, TTL: ttl})
	if err != nil {
		return writeError(c, err)
	}
	if dup {
		return c.Status(200).JSON(map[string]any{"seq": m.Seq, "duplicate": true})
	}
	list, err := s.Groups.Roster(ctx, in.Tenant, in.Conv)
	if err == nil {
		ev, _ := jsonMarshal(m)
		for _, mem := range list {
			// from is empty: nobody sent this as far as the service knows.
			_ = s.Notify(context.Background(), in.Tenant, mem.User, "msg.new", ev, "")
		}
		if s.hook.enabled() {
			users := make([]string, len(list))
			for i, mem := range list {
				users[i] = mem.User
			}
			s.hook.emit(HookEvent{Type: "msg.new", Tenant: in.Tenant, Conv: in.Conv, Seq: m.Seq, Msg: in.ID, Size: len(in.Body), Epoch: in.Epoch,
				Recipients: users, Connected: s.hubs.connectedAmong(in.Tenant, users, "")})
		}
	}
	return c.Status(200).JSON(map[string]any{"seq": m.Seq, "sent_at": m.Sent})
}

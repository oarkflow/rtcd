package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oarkflow/fh"
	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/auth"
	"github.com/oarkflow/rtcd/chat"
)

// Attachments.
//
// The client encrypts a file in its own browser or app and uploads the
// ciphertext in parts; the server keeps bytes it cannot read. The key travels
// inside an encrypted message, with the file's id. Parts are written in place,
// so an upload that is cut off resumes from file.status; the stored bytes are
// checked against the SHA-256 the client announced before the file is usable.
//
// A file may be fetched only by a member of the conversation it was uploaded
// to, with a token or with a link that file.link gave that member.
const (
	defaultChunk   = 1 << 20
	maxChunk       = 4 << 20
	linkTTL        = 5 * time.Minute
	uploadTTL      = 24 * time.Hour
	defaultMaxFile = 256 << 20
)

func (s *Server) filePath(tenant, id string) string {
	t := sha256.Sum256([]byte(tenant))
	return filepath.Join(s.cfg.AttachDir, hex.EncodeToString(t[:8]), id+".bin")
}

func (s *Server) partsPath(tenant, id string) string { return s.filePath(tenant, id) + ".parts" }

func (s *Server) removeFile(tenant, id string) {
	s.parts.Delete(tenant + "\x00" + id)
	_ = os.Remove(s.filePath(tenant, id))
	_ = os.Remove(s.partsPath(tenant, id))
	_ = s.Chat.DeleteFile(context.Background(), tenant, id)
}

func (s *Server) registerFiles() {
	f := func(name string, run func(o *opCtx, raw json.RawMessage) (any, error)) {
		s.register(opDef{name: "file." + name, scope: auth.ScopeChat, run: func(o *opCtx, raw json.RawMessage) (any, error) {
			if s.cfg.AttachDir == "" {
				return nil, &apiError{404, "attachments_disabled", ""}
			}
			return run(o, raw)
		}})
	}
	// file.init {conv, size, sha256, chunk?}
	f("init", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			Conv   string `json:"conv"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
			Chunk  int64  `json:"chunk"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.Conv
		if _, err := s.conv(o, in.Conv); err != nil {
			return nil, err
		}
		if in.Chunk == 0 {
			in.Chunk = defaultChunk
		}
		if in.Chunk < 0 || in.Chunk > maxChunk {
			return nil, bad("chunk must be between 1 and 4194304 bytes")
		}
		fl, err := s.Chat.NewFile(o, o.sess.who.Tenant, in.Conv, o.sess.who.ID, in.Size, in.Chunk, in.SHA256, uploadTTL,
			chat.Quota{MaxFile: s.cfg.MaxFileBytes, PendingPerUser: 10, TenantBytes: s.cfg.TenantFileBytes})
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(s.filePath(o.sess.who.Tenant, fl.ID)), 0o750); err == nil {
			err = createSparse(s.filePath(o.sess.who.Tenant, fl.ID), fl.Size)
			if err == nil {
				err = os.WriteFile(s.partsPath(o.sess.who.Tenant, fl.ID), make([]byte, fl.Chunks()), 0o600)
			}
		}
		if err != nil {
			s.removeFile(o.sess.who.Tenant, fl.ID)
			return nil, err
		}
		o.note("size", fl.Size)
		return map[string]any{"file": fl, "chunks": fl.Chunks(), "upload": "/v1/files/" + fl.ID + "/parts/{n}"}, nil
	})
	// file.status {file}: what has arrived, to resume an upload.
	f("status", func(o *opCtx, raw json.RawMessage) (any, error) {
		fl, err := s.fileFor(o, raw)
		if err != nil {
			return nil, err
		}
		have := []int64{}
		if fl.State == chat.Uploading {
			b, _ := os.ReadFile(s.partsPath(o.sess.who.Tenant, fl.ID))
			for i, v := range b {
				if v == 1 {
					have = append(have, int64(i))
				}
			}
		}
		return map[string]any{"file": fl, "chunks": fl.Chunks(), "have": have}, nil
	})
	f("complete", func(o *opCtx, raw json.RawMessage) (any, error) {
		fl, err := s.fileFor(o, raw)
		if err != nil {
			return nil, err
		}
		if fl.Owner != o.sess.who.ID {
			return nil, chat.ErrForbidden
		}
		if fl.State != chat.Uploading {
			return nil, chat.ErrState
		}
		b, _ := os.ReadFile(s.partsPath(o.sess.who.Tenant, fl.ID))
		if int64(len(b)) != fl.Chunks() {
			return nil, chat.ErrState
		}
		for _, v := range b {
			if v != 1 {
				return nil, conflict("parts_missing")
			}
		}
		sum, err := hashFile(s.filePath(o.sess.who.Tenant, fl.ID))
		if err != nil {
			return nil, err
		}
		if sum != fl.SHA256 {
			s.removeFile(o.sess.who.Tenant, fl.ID) // never keep bytes that are not what was announced
			return nil, &apiError{422, "checksum_mismatch", ""}
		}
		_ = os.Remove(s.partsPath(o.sess.who.Tenant, fl.ID))
		s.parts.Delete(o.sess.who.Tenant + "\x00" + fl.ID)
		if err := s.Chat.SetReady(o, o.sess.who.Tenant, fl.ID, s.cfg.FileRetention); err != nil {
			return nil, err
		}
		fl.State = chat.Ready
		return map[string]any{"file": fl}, nil
	})
	// file.link {file}: a URL for a browser to fetch the file with, no header needed.
	f("link", func(o *opCtx, raw json.RawMessage) (any, error) {
		fl, err := s.fileFor(o, raw)
		if err != nil {
			return nil, err
		}
		if fl.State != chat.Ready {
			return nil, chat.ErrState
		}
		exp := s.cfg.Now().Add(linkTTL).Unix()
		q := "exp=" + strconv.FormatInt(exp, 10) + "&u=" + url.QueryEscape(o.sess.who.ID) + "&sig=" + s.sign(o.sess.who.Tenant, fl.ID, o.sess.who.ID, exp)
		return map[string]any{"url": "/v1/files/" + fl.ID + "/blob?" + q + "&t=" + url.QueryEscape(o.sess.who.Tenant), "expires_in": int(linkTTL.Seconds())}, nil
	})
	f("delete", func(o *opCtx, raw json.RawMessage) (any, error) {
		in, err := decode[struct {
			File string `json:"file"`
		}](raw)
		if err != nil {
			return nil, err
		}
		o.target = in.File
		fl, err := s.Chat.File(o, o.sess.who.Tenant, in.File)
		if err != nil {
			return nil, err
		}
		ci, err := s.conv(o, fl.Conv)
		if err != nil {
			return nil, chat.ErrNotFound
		}
		if fl.Owner != o.sess.who.ID && !ci.admin[o.sess.who.ID] {
			return nil, chat.ErrForbidden
		}
		s.removeFile(o.sess.who.Tenant, fl.ID)
		return nil, nil
	})
}

// fileFor loads the file named in the request, if the caller is in its conversation.
func (s *Server) fileFor(o *opCtx, raw json.RawMessage) (chat.File, error) {
	in, err := decode[struct {
		File string `json:"file"`
	}](raw)
	if err != nil {
		return chat.File{}, err
	}
	o.target = in.File
	fl, err := s.Chat.File(o, o.sess.who.Tenant, in.File)
	if err != nil {
		return chat.File{}, err
	}
	if _, err := s.conv(o, fl.Conv); err != nil {
		return chat.File{}, chat.ErrNotFound // a file in a conversation you are not in does not exist
	}
	return fl, nil
}

func (s *Server) sign(tenant, id, user string, exp int64) string {
	m := hmac.New(sha256.New, []byte("rtcd-file-link\x00"+s.cfg.TokenSecret))
	m.Write([]byte(tenant + "\x00" + id + "\x00" + user + "\x00" + strconv.FormatInt(exp, 10)))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) mountFiles(app *fh.App) {
	app.Add("PUT", "/v1/files/:id/parts/:n", s.cors(s.putPart))
	app.Add("GET", "/v1/files/:id/blob", s.cors(s.getBlob))
	app.Options("/v1/files/:id/parts/:n", s.preflight)
	app.Options("/v1/files/:id/blob", s.preflight)
	for _, r := range []route{
		{"POST", "/v1/files", "file.init", ""},
		{"GET", "/v1/files/:id", "file.status", "file"},
		{"POST", "/v1/files/:id/complete", "file.complete", "file"},
		{"POST", "/v1/files/:id/link", "file.link", "file"},
		{"POST", "/v1/files/:id/delete", "file.delete", "file"},
	} {
		app.Add(r.method, r.path, s.cors(s.rest(r)))
		app.Options(r.path, s.preflight)
	}
	for _, r := range []route{
		{"POST", "/v1/messages", "msg.send", ""},
		{"POST", "/v1/messages/history", "msg.history", ""},
		{"POST", "/v1/messages/read", "msg.read", ""},
		{"POST", "/v1/messages/delete", "msg.delete", ""},
	} {
		app.Add(r.method, r.path, s.cors(s.rest(r)))
		app.Options(r.path, s.preflight)
	}
}

// userSession authenticates an HTTP request as a user.
func (s *Server) userSession(c fh.Ctx) (*session, error) {
	ip := strings.Clone(c.IP())
	p, err := s.identify(c, false, ip, "http")
	if err != nil {
		return nil, err
	}
	if p.IsService() {
		if p, err = p.WithUser(strings.Clone(c.Get("X-RTC-User"))); err != nil {
			return nil, bad("X-RTC-User is not a valid user name")
		}
	}
	return newSession(p, ip, "http", "", s.cfg.Now()), nil
}

func (s *Server) putPart(c fh.Ctx) error {
	if s.cfg.AttachDir == "" {
		return writeError(c, &apiError{404, "attachments_disabled", ""})
	}
	sess, err := s.userSession(c)
	if err == nil && !sess.allows(auth.ScopeChat) {
		err = denied("scope_missing")
	}
	if err != nil {
		return writeError(c, err)
	}
	if !s.opLimit.allow(sess.who.Tenant+"\x00"+sess.who.ID+"\x00"+sess.service, s.cfg.Now()) {
		return writeError(c, &apiError{429, "rate_limited", ""})
	}
	o := &opCtx{Context: c.Context(), s: s, sess: sess, target: strings.Clone(c.Params("id"))}
	err = func() error {
		n, perr := strconv.ParseInt(c.Params("n"), 10, 64)
		fl, ferr := s.partMeta(o, sess.who.Tenant, o.target)
		switch {
		case ferr != nil:
			return ferr
		case perr != nil || n < 0 || n >= fl.Chunks():
			return bad("part number out of range")
		case fl.Owner != sess.who.ID:
			return chat.ErrNotFound
		case fl.State != chat.Uploading:
			return chat.ErrState
		}
		want := fl.Chunk
		if n == fl.Chunks()-1 {
			want = fl.Size - n*fl.Chunk
		}
		body := c.Body()
		if int64(len(body)) != want {
			return &apiError{400, "wrong_part_size", ""}
		}
		path := s.filePath(sess.who.Tenant, fl.ID)
		fh2, oerr := os.OpenFile(path, os.O_WRONLY, 0)
		if oerr != nil {
			return chat.ErrNotFound
		}
		defer fh2.Close()
		if _, werr := fh2.WriteAt(body, n*fl.Chunk); werr != nil {
			return werr
		}
		pf, perr2 := os.OpenFile(s.partsPath(sess.who.Tenant, fl.ID), os.O_WRONLY, 0)
		if perr2 != nil {
			return chat.ErrNotFound
		}
		defer pf.Close()
		_, perr2 = pf.WriteAt([]byte{1}, n)
		return perr2
	}()
	if err != nil {
		return writeError(c, err)
	}
	return c.Status(200).JSON(map[string]bool{"ok": true})
}

func (s *Server) getBlob(c fh.Ctx) error {
	if s.cfg.AttachDir == "" {
		return writeError(c, &apiError{404, "attachments_disabled", ""})
	}
	id := strings.Clone(c.Params("id"))
	var tenant, user string
	if sig := c.Query("sig"); sig != "" {
		// A link: the signature binds the file to one tenant and user until it expires.
		tenant, user = strings.Clone(c.Query("t")), strings.Clone(c.Query("u"))
		exp, _ := strconv.ParseInt(c.Query("exp"), 10, 64)
		if !s.insecureOK(c) || exp < s.cfg.Now().Unix() || !hmac.Equal([]byte(sig), []byte(s.sign(tenant, id, user, exp))) {
			return writeError(c, unauth("unauthenticated"))
		}
	} else {
		sess, err := s.userSession(c)
		if err == nil && !sess.allows(auth.ScopeChat) {
			err = denied("scope_missing")
		}
		if err != nil {
			return writeError(c, err)
		}
		tenant, user = sess.who.Tenant, sess.who.ID
	}
	sess := newSession(auth.Principal{Tenant: tenant, User: user, Scopes: auth.ScopeChat}, strings.Clone(c.IP()), "http", "", s.cfg.Now())
	o := &opCtx{Context: c.Context(), s: s, sess: sess, target: id}
	fl, err := s.Chat.File(o, tenant, id)
	if err == nil {
		_, err = s.conv(o, fl.Conv)
		if err != nil {
			err = chat.ErrNotFound
		} else if fl.State != chat.Ready {
			err = chat.ErrState
		}
	}
	s.record(audit.Event{Tenant: tenant, Actor: user, Action: "file.download", Target: id, Outcome: outcomeOf2(err), IP: sess.ip, Transport: "http"})
	if err != nil {
		return writeError(c, err)
	}
	// Ciphertext: never sniffed, never rendered, never cached by a shared cache.
	c.Set("Content-Type", "application/octet-stream")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Content-Disposition", "attachment")
	c.Set("Cache-Control", "private, no-store")
	c.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	return c.SendFile(s.filePath(tenant, id))
}

// insecureOK applies the TLS rule to a request that is authenticated by a link.
func (s *Server) insecureOK(c fh.Ctx) bool { return s.cfg.InsecureHTTP || transportIsSecure(c) }

func outcomeOf2(err error) string {
	if err != nil {
		return audit.Denied
	}
	return audit.OK
}

func createSparse(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sweepFiles removes uploads that were never finished and files past retention.
func (s *Server) sweepFiles() {
	if s.cfg.AttachDir == "" {
		return
	}
	list, err := s.Chat.Expired(context.Background(), 200)
	if err != nil {
		return
	}
	for _, p := range list {
		s.removeFile(p[0], p[1])
	}
}

// partMeta is File for the part-upload path: a file under upload has fixed size,
// part size and owner, and a big file is hundreds of requests, so the record is
// kept for a few seconds instead of being read for every part.
func (s *Server) partMeta(o *opCtx, tenant, id string) (chat.File, error) {
	key := tenant + "\x00" + id
	now := s.cfg.Now()
	if v, ok := s.parts.Load(key); ok {
		if e := v.(partEntry); now.Before(e.until) {
			return e.f, nil
		}
	}
	f, err := s.Chat.File(o, tenant, id)
	if err == nil && f.State == chat.Uploading {
		s.parts.Store(key, partEntry{f, now.Add(10 * time.Second)})
	}
	return f, err
}

type partEntry struct {
	f     chat.File
	until time.Time
}

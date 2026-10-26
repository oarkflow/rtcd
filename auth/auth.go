// Package auth identifies the callers of the service.
//
// Two kinds of caller exist. A backend service holds an API key that belongs to
// one tenant; it acts for any user of that tenant, naming the user in a header,
// and it may mint tokens. An end user holds a token a backend minted for them:
// signed, short-lived, good for one user of one tenant and nothing else, and
// safe to hand to a browser.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ErrUnauthenticated is returned for a missing, malformed, wrong or expired credential.
var ErrUnauthenticated = errors.New("auth: unauthenticated")

const tokenPrefix = "rtcu1."

// MinKeyLen is the shortest API key or token secret accepted.
const MinKeyLen = 24

// ServiceKey is one backend service's credential.
type ServiceKey struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Tenant string `json:"tenant"`
}

// Scopes say what a token may do. A service key may do everything.
type Scopes uint8

// The scopes a user token can carry.
const (
	ScopeCalls  Scopes = 1 << iota // calls and group-call media signaling
	ScopeGroups                    // creating and managing groups
	ScopeChat                      // messages and attachments
	// UserScopes is what a token carries when none are asked for.
	UserScopes = ScopeCalls | ScopeGroups | ScopeChat
)

// ParseScopes turns names into Scopes. No names means UserScopes.
func ParseScopes(names []string) (Scopes, error) {
	if len(names) == 0 {
		return UserScopes, nil
	}
	var sc Scopes
	for _, n := range names {
		switch n {
		case "calls":
			sc |= ScopeCalls
		case "groups":
			sc |= ScopeGroups
		case "chat":
			sc |= ScopeChat
		default:
			return 0, fmt.Errorf("auth: unknown scope %q", n)
		}
	}
	return sc, nil
}

// Names lists the scopes.
func (s Scopes) Names() []string {
	var out []string
	if s&ScopeCalls != 0 {
		out = append(out, "calls")
	}
	if s&ScopeGroups != 0 {
		out = append(out, "groups")
	}
	if s&ScopeChat != 0 {
		out = append(out, "chat")
	}
	return out
}

// Principal is who is calling.
type Principal struct {
	Tenant  string
	User    string // empty for a service until it names a user
	Service string // the service key's name, when a service is calling
	Scopes  Scopes
	// Expires is when a user token stops working; zero for a service key.
	Expires time.Time
}

// IsService reports whether a backend service (not an end user) is calling.
func (p Principal) IsService() bool { return p.Service != "" }

// Authenticator checks credentials.
type Authenticator struct {
	keys   []keyEntry
	secret []byte
	now    func() time.Time

	rmu     sync.Mutex
	revoked map[string]int64 // tenant\x00user -> unix ns: tokens issued at or before this are refused
	retain  time.Duration
}

type keyEntry struct {
	name, tenant string
	digest       [32]byte
}

// New builds an Authenticator. tokenSecret signs user tokens.
func New(keys []ServiceKey, tokenSecret string, now func() time.Time) (*Authenticator, error) {
	if len(tokenSecret) < MinKeyLen {
		return nil, fmt.Errorf("auth: the token secret must be at least %d characters", MinKeyLen)
	}
	if now == nil {
		now = time.Now
	}
	a := &Authenticator{secret: []byte(tokenSecret), now: now, revoked: map[string]int64{}, retain: 24 * time.Hour}
	seenKey, seenName := map[string]bool{}, map[string]bool{}
	for _, k := range keys {
		switch {
		case k.Name == "" || k.Tenant == "":
			return nil, errors.New("auth: every API key needs a name and a tenant")
		case len(k.Key) < MinKeyLen:
			return nil, fmt.Errorf("auth: API key %q is shorter than %d characters", k.Name, MinKeyLen)
		case strings.HasPrefix(k.Key, tokenPrefix):
			return nil, fmt.Errorf("auth: API key %q looks like a user token", k.Name)
		case seenKey[k.Key] || seenName[k.Name]:
			return nil, fmt.Errorf("auth: API key %q duplicates another", k.Name)
		case !ValidName(k.Tenant):
			return nil, fmt.Errorf("auth: tenant %q has characters that are not allowed", k.Tenant)
		}
		seenKey[k.Key], seenName[k.Name] = true, true
		a.keys = append(a.keys, keyEntry{name: k.Name, tenant: k.Tenant, digest: sha256.Sum256([]byte(k.Key))})
	}
	return a, nil
}

// ValidName reports whether s can be a user or tenant name: 1 to 128 printable
// characters, none of them a control character or the separator used inside
// topics.
func ValidName(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0x1f || r == utf8.RuneError {
			return false
		}
	}
	return s == strings.TrimSpace(s)
}

// Bearer extracts the credential from an Authorization header value.
func Bearer(header string) string {
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// Authenticate resolves a credential. A service key gives a Principal with no
// user yet; the caller names the user (see Principal.WithUser).
func (a *Authenticator) Authenticate(credential string) (Principal, error) {
	if credential == "" {
		return Principal{}, ErrUnauthenticated
	}
	if strings.HasPrefix(credential, tokenPrefix) {
		return a.verify(credential)
	}
	d := sha256.Sum256([]byte(credential))
	var found *keyEntry
	for i := range a.keys { // every key is compared, so timing does not say which exist
		if subtle.ConstantTimeCompare(d[:], a.keys[i].digest[:]) == 1 {
			found = &a.keys[i]
		}
	}
	if found == nil {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Tenant: found.tenant, Service: found.name, Scopes: UserScopes}, nil
}

// WithUser lets a service act as a user of its tenant.
func (p Principal) WithUser(user string) (Principal, error) {
	if !p.IsService() {
		return Principal{}, ErrUnauthenticated
	}
	if !ValidName(user) {
		return Principal{}, errors.New("auth: the user name is not valid")
	}
	p.User = user
	return p, nil
}

type claims struct {
	Tenant  string `json:"t"`
	User    string `json:"u"`
	Expires int64  `json:"e"`
	Issued  int64  `json:"i,omitempty"` // unix nanoseconds; lets a revocation cut off older tokens
	Scopes  Scopes `json:"s"`
}

// Mint signs a token for one user of one tenant, good for the given scopes.
func (a *Authenticator) Mint(tenant, user string, ttl time.Duration, scopes Scopes) (string, time.Time, error) {
	if !ValidName(tenant) || !ValidName(user) {
		return "", time.Time{}, errors.New("auth: the user name is not valid")
	}
	if scopes == 0 || scopes&^UserScopes != 0 {
		return "", time.Time{}, errors.New("auth: a token needs at least one valid scope")
	}
	exp := a.now().Add(ttl)
	body, _ := json.Marshal(claims{Tenant: tenant, User: user, Expires: exp.Unix(), Issued: a.now().UnixNano(), Scopes: scopes})
	payload := base64.RawURLEncoding.EncodeToString(body)
	return tokenPrefix + payload + "." + a.sign(payload), exp, nil
}

func (a *Authenticator) sign(payload string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *Authenticator) verify(token string) (Principal, error) {
	rest := strings.TrimPrefix(token, tokenPrefix)
	payload, sig, ok := strings.Cut(rest, ".")
	if !ok || len(token) > 1024 {
		return Principal{}, ErrUnauthenticated
	}
	if !hmac.Equal([]byte(sig), []byte(a.sign(payload))) {
		return Principal{}, ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	var c claims
	if json.Unmarshal(raw, &c) != nil || !ValidName(c.Tenant) || !ValidName(c.User) || a.now().Unix() >= c.Expires {
		return Principal{}, ErrUnauthenticated
	}
	if c.Scopes == 0 || c.Scopes&^UserScopes != 0 {
		return Principal{}, ErrUnauthenticated
	}
	if a.isRevoked(c.Tenant, c.User, c.Issued) {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Tenant: c.Tenant, User: c.User, Scopes: c.Scopes, Expires: time.Unix(c.Expires, 0)}, nil
}

// SetRetention is how long a revocation is remembered: it must be at least the
// longest life a token can have, after which no older token can still be valid.
func (a *Authenticator) SetRetention(d time.Duration) {
	if d > 0 {
		a.rmu.Lock()
		a.retain = d
		a.rmu.Unlock()
	}
}

// Revoke refuses every token already minted for the user (tokens minted after
// this call work). It is held in memory: a restart forgets it, but tokens are
// short-lived, and a node that has not seen the revocation is why a multi-node
// deployment must send it to every node.
func (a *Authenticator) Revoke(tenant, user string) int64 {
	now := a.now().UnixNano()
	a.rmu.Lock()
	defer a.rmu.Unlock()
	for k, at := range a.revoked {
		if now-at > a.retain.Nanoseconds() {
			delete(a.revoked, k)
		}
	}
	a.revoked[tenant+"\x00"+user] = now
	return now
}

// RevokeAt applies a revocation made elsewhere (another node, an earlier run).
func (a *Authenticator) RevokeAt(tenant, user string, at int64) {
	a.rmu.Lock()
	defer a.rmu.Unlock()
	if k := tenant + "\x00" + user; a.revoked[k] < at {
		a.revoked[k] = at
	}
}

// Revoked reports whether tokens for the user issued at or before issued (unix ns) are refused.
func (a *Authenticator) Revoked(tenant, user string, issued int64) bool {
	return a.isRevoked(tenant, user, issued)
}

func (a *Authenticator) isRevoked(tenant, user string, issued int64) bool {
	a.rmu.Lock()
	at, ok := a.revoked[tenant+"\x00"+user]
	a.rmu.Unlock()
	return ok && issued <= at
}

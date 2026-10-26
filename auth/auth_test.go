package auth

import (
	"strings"
	"testing"
	"time"
)

const secret = "0123456789abcdef0123456789abcdef"

func newAuth(t *testing.T, now *time.Time) *Authenticator {
	t.Helper()
	a, err := New([]ServiceKey{
		{Name: "chat", Key: "chat-service-key-0123456789", Tenant: "acme"},
		{Name: "shop", Key: "shop-service-key-0123456789", Tenant: "zeta"},
	}, secret, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestServiceKeysBelongToOneTenantEach(t *testing.T) {
	now := time.Now()
	a := newAuth(t, &now)
	p, err := a.Authenticate("chat-service-key-0123456789")
	if err != nil || p.Tenant != "acme" || !p.IsService() || p.User != "" {
		t.Fatalf("%+v %v", p, err)
	}
	if q, _ := a.Authenticate("shop-service-key-0123456789"); q.Tenant != "zeta" {
		t.Fatalf("%+v", q)
	}
	for _, bad := range []string{"", "nope", "chat-service-key-012345678", "chat-service-key-0123456789 ", strings.ToUpper("chat-service-key-0123456789")} {
		if _, err := a.Authenticate(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestAServiceActsOnlyAsValidUsersOfItsOwnTenant(t *testing.T) {
	now := time.Now()
	a := newAuth(t, &now)
	p, _ := a.Authenticate("chat-service-key-0123456789")
	got, err := p.WithUser("ada")
	if err != nil || got.User != "ada" || got.Tenant != "acme" {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"", " ", "a\x1fb", "a\nb", strings.Repeat("x", 129), "\xff"} {
		if _, err := p.WithUser(bad); err == nil {
			t.Errorf("user %q was accepted", bad)
		}
	}
	tok, _, _ := a.Mint("acme", "ada", time.Minute, UserScopes)
	u, _ := a.Authenticate(tok)
	if _, err := u.WithUser("bob"); err == nil {
		t.Fatal("an end user acted as somebody else")
	}
}

func TestTokensAreSignedExpireAndCannotBeAltered(t *testing.T) {
	now := time.Now()
	a := newAuth(t, &now)
	tok, exp, err := a.Mint("acme", "ada", 10*time.Minute, UserScopes)
	if err != nil || !exp.After(now) {
		t.Fatal(err)
	}
	p, err := a.Authenticate(tok)
	if err != nil || p.Tenant != "acme" || p.User != "ada" || p.IsService() {
		t.Fatalf("%+v %v", p, err)
	}
	now = now.Add(9 * time.Minute)
	if _, err := a.Authenticate(tok); err != nil {
		t.Fatalf("a token inside its lifetime: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := a.Authenticate(tok); err == nil {
		t.Fatal("an expired token was accepted")
	}
	now = time.Now()
	// Change the user, the tenant, the signature, or sign with another secret.
	other, _ := New(nil, "another-secret-another-secret-0", func() time.Time { return now })
	forged, _, _ := other.Mint("acme", "ada", time.Hour, UserScopes)
	parts := strings.SplitN(tok, ".", 3)
	mut := func(s string) string { b := []byte(s); b[len(b)/2] ^= 1; return string(b) }
	for name, bad := range map[string]string{
		"another secret": forged,
		"payload edited": parts[0] + "." + mut(parts[1]) + "." + parts[2],
		"signature cut":  tok[:len(tok)-4],
		"no signature":   parts[0] + "." + parts[1],
		"garbage":        "rtcu1.x.y",
		"empty payload":  "rtcu1..",
	} {
		if _, err := a.Authenticate(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A token for tenant A cannot be turned into one for tenant B by editing it.
	tb, _, _ := a.Mint("zeta", "ada", time.Hour, UserScopes)
	pa, _ := a.Authenticate(tok)
	pb, _ := a.Authenticate(tb)
	if pa.Tenant == pb.Tenant {
		t.Fatal("tenants are not part of the token")
	}
}

func TestConfigurationMistakesAreRefused(t *testing.T) {
	good := ServiceKey{Name: "a", Key: "chat-service-key-0123456789", Tenant: "acme"}
	cases := map[string][]ServiceKey{
		"short key":       {{Name: "a", Key: "short", Tenant: "t"}},
		"no tenant":       {{Name: "a", Key: good.Key}},
		"duplicate key":   {good, {Name: "b", Key: good.Key, Tenant: "x"}},
		"duplicate name":  {good, {Name: "a", Key: "another-key-0123456789abcd", Tenant: "x"}},
		"token lookalike": {{Name: "a", Key: "rtcu1.0123456789abcdefghijklmnop", Tenant: "t"}},
		"bad tenant":      {{Name: "a", Key: good.Key, Tenant: "a\x1fb"}},
	}
	for name, keys := range cases {
		if _, err := New(keys, secret, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New([]ServiceKey{good}, "short", nil); err == nil {
		t.Error("a short token secret was accepted")
	}
}

func TestBearerParsing(t *testing.T) {
	for in, want := range map[string]string{"Bearer abc": "abc", "bearer  abc ": "abc", "Basic abc": "", "Bearer": "", "": "", "Bearerabc": ""} {
		if got := Bearer(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestTokenScopesAreSignedAndLimitWhatATokenMayDo(t *testing.T) {
	now := time.Now()
	a := newAuth(t, &now)
	tok, exp, err := a.Mint("acme", "ada", time.Minute, ScopeCalls)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(tok)
	if err != nil || p.Scopes != ScopeCalls || p.Scopes&ScopeGroups != 0 || !p.Expires.Equal(time.Unix(exp.Unix(), 0)) {
		t.Fatalf("%+v %v", p, err)
	}
	// Widening the scopes by editing the token breaks the signature.
	parts := strings.SplitN(tok, ".", 3)
	wide, _, _ := a.Mint("acme", "ada", time.Minute, UserScopes)
	forged := parts[0] + "." + strings.SplitN(wide, ".", 3)[1] + "." + parts[2]
	if _, err := a.Authenticate(forged); err == nil {
		t.Fatal("a token's scopes were widened")
	}
	for _, bad := range []Scopes{0, 8, 255} {
		if _, _, err := a.Mint("acme", "ada", time.Minute, bad); err == nil {
			t.Errorf("scopes %d were accepted", bad)
		}
	}
	svc, _ := a.Authenticate("chat-service-key-0123456789")
	if svc.Scopes != UserScopes || !svc.Expires.IsZero() {
		t.Fatalf("%+v", svc)
	}
	if sc, err := ParseScopes([]string{"calls", "groups", "chat"}); err != nil || sc != UserScopes {
		t.Fatalf("%v %v", sc, err)
	}
	if sc, _ := ParseScopes(nil); sc != UserScopes {
		t.Fatal("no scopes should mean the default")
	}
	if _, err := ParseScopes([]string{"admin"}); err == nil {
		t.Fatal("an unknown scope was accepted")
	}
}

func TestRevokeRefusesEarlierTokensAndNotLaterOnes(t *testing.T) {
	now := time.Now()
	a, _ := New([]ServiceKey{{Name: "chat", Key: "chat-service-key-0123456789", Tenant: "acme"}}, "secret-secret-secret-secret-1", func() time.Time { return now })
	old, _, _ := a.Mint("acme", "ada", time.Hour, UserScopes)
	other, _, _ := a.Mint("acme", "bob", time.Hour, UserScopes)
	now = now.Add(time.Second)
	a.Revoke("acme", "ada")
	if _, err := a.Authenticate(old); err == nil {
		t.Fatal("a revoked user's token still works")
	}
	if _, err := a.Authenticate(other); err != nil {
		t.Fatal("revoking one user cut off another")
	}
	now = now.Add(time.Second)
	fresh, _, _ := a.Mint("acme", "ada", time.Hour, UserScopes)
	if _, err := a.Authenticate(fresh); err != nil {
		t.Fatal("a token minted after the revocation was refused")
	}
}

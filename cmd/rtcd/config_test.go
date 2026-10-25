package main

import (
	"strings"
	"testing"
	"time"
)

const good = `
listen "127.0.0.1:8480"
insecure_http false
database { driver "sqlite"  dsn "file:.data/rtcd.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" }
audit    { dsn "file:.data/audit.db"  file ".data/audit.jsonl"  queue 4096 }

key "chat"  { key env.required("T_KEY_CHAT")  tenant "acme" }
key "shop"  { key "literal-key-0123456789-abcdef"  tenant "zeta" }
token_secret env.required("T_SECRET")
max_token_ttl "30m"

allowed_origins ["https://app.example.com", "http://localhost:8080"]
stun_urls ["stun:stun.example.com:3478"]
groups { max_owned 50  max_members 100 }
limits { shards 16  max_connections 5000  ops_per_second 150.5  ops_burst 300 }
udp_port_min 50000
udp_port_max 50100
record_dir ".data/rec"
`

func TestAConfigInBCLIsRead(t *testing.T) {
	t.Setenv("T_KEY_CHAT", "chat-key-from-the-environment-01")
	t.Setenv("T_SECRET", "token-secret-from-the-environment-01")
	fc, err := parseConfig([]byte(good), ".")
	if err != nil {
		t.Fatal(err)
	}
	if fc.Listen != "127.0.0.1:8480" || fc.Database.Driver != "sqlite" || fc.Audit.Queue != 4096 || fc.Audit.File != ".data/audit.jsonl" {
		t.Fatalf("%+v", fc)
	}
	if len(fc.Keys) != 2 || fc.Keys[0] != (configKey{"chat", "chat-key-from-the-environment-01", "acme"}) || fc.Keys[1].Key != "literal-key-0123456789-abcdef" || fc.Keys[1].Tenant != "zeta" {
		t.Fatalf("keys: %+v", fc.Keys)
	}
	if fc.TokenSecret != "token-secret-from-the-environment-01" || len(fc.AllowedOrigins) != 2 || fc.Groups.MaxMembers != 100 || fc.Limits.OpsPerSecond != 150.5 || fc.Limits.Shards != 16 {
		t.Fatalf("%+v", fc)
	}
	cfg, dbs, err := build(fc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, d := range dbs {
			d.Close()
		}
	}()
	if cfg.MaxTokenTTL != 30*time.Minute || cfg.UDPPortMin != 50000 || cfg.UDPPortMax != 50100 || cfg.AuditDB == nil || cfg.AuditQueue != 4096 || cfg.MaxOwnedGroups != 50 || cfg.RecordDir != ".data/rec" {
		t.Fatalf("%+v", cfg)
	}
	if len(cfg.Keys) != 2 || cfg.Keys[1].Name != "shop" || len(dbs) != 2 {
		t.Fatalf("%+v %d", cfg.Keys, len(dbs))
	}
}

func TestMistakesInTheConfigAreErrorsNotDefaults(t *testing.T) {
	t.Setenv("T_KEY_CHAT", "chat-key-from-the-environment-01")
	t.Setenv("T_SECRET", "token-secret-from-the-environment-01")
	ok := strings.Replace(good, "env.required(\"T_SECRET\")", "\"token-secret-from-the-environment-01\"", 1)
	cases := map[string]struct{ src, want string }{
		"a misspelt setting":        {ok + "\nlisten_on \"x\"\n", "listen_on"},
		"a misspelt nested setting": {strings.Replace(ok, "ops_burst 300", "ops_brust 300", 1), "ops_brust"},
		"an unknown labeled block":  {ok + "\nserver \"x\" { a 1 }\n", `unknown block "server"`},
		"an unknown plain block":    {ok + "\nserver { a 1 }\n", "server"},
		"a key block with no name":  {ok + "\nkey { key \"abcdefghijklmnopqrstuvwxyz\" tenant \"t\" }\n", "needs a name"},
		"a misspelt key setting":    {strings.Replace(ok, `tenant "zeta"`, `tennant "zeta"`, 1), "tennant"},
		"a wrong type":              {strings.Replace(ok, "queue 4096", `queue "lots"`, 1), "queue"},
		"a missing required secret": {strings.Replace(ok, `"token-secret-from-the-environment-01"`, `env.required("T_NOT_SET_ANYWHERE")`, 1), "T_NOT_SET_ANYWHERE"},
		"a syntax error":            {ok + "\nkey \"x\" {\n", ""},
	}
	for name, c := range cases {
		_, err := parseConfig([]byte(c.src), ".")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if c.want != "" && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error does not say what is wrong (%q): %v", name, c.want, err)
		}
	}
	if _, err := parseConfig([]byte(ok), "."); err != nil {
		t.Fatalf("the unmodified config should load: %v", err)
	}
}

func TestOnlySQLiteIsLinkedIn(t *testing.T) {
	fc := fileConfig{}
	fc.Database.Driver = "postgres"
	if _, _, err := build(fc); err == nil || !strings.Contains(err.Error(), "sqlite") {
		t.Fatalf("%v", err)
	}
	fc.Database.Driver, fc.UDPPortMin = "", -1
	if _, _, err := build(fc); err == nil {
		t.Fatal("a negative port was accepted")
	}
}

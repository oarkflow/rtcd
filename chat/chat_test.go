package chat_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/rtcd/chat"
	_ "modernc.org/sqlite"
)

// A database made by v0.0.6 has rtc_messages without epoch and expires_at. It
// opens, keeps its messages, and takes new ones.
func TestAnOlderMessagesTableIsUpgradedInPlace(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "old.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	bg := context.Background()
	for _, q := range []string{
		`CREATE TABLE rtc_messages (tenant VARCHAR(191) NOT NULL, conv VARCHAR(191) NOT NULL, seq BIGINT NOT NULL,
			id VARCHAR(191) NOT NULL, sender VARCHAR(191) NOT NULL, sent_at BIGINT NOT NULL, body TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant, conv, seq))`,
		`INSERT INTO rtc_messages VALUES ('t','c',1,'old','ada',1000,'ciphertext',0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ { // opening twice is fine
		if _, err = chat.Open(bg, db, chat.Options{Dialect: "sqlite"}); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := chat.Open(bg, db, chat.Options{Dialect: "sqlite"})
	m, _, err := s.Send(bg, chat.SendIn{Tenant: "t", Conv: "c", Sender: "bob", ID: "new", Body: "x", Epoch: 2, TTL: time.Hour})
	if err != nil || m.Seq != 2 || m.Epoch != 2 || m.Expires == nil {
		t.Fatalf("send after upgrade: %+v %v", m, err)
	}
	h, err := s.History(bg, "t", "c", 0, 0, 10)
	if err != nil || len(h) != 2 || h[0].Body != "ciphertext" || h[0].Epoch != 0 || h[0].Expires != nil {
		t.Fatalf("history after upgrade: %+v %v", h, err)
	}
}

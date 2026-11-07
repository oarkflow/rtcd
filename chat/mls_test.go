package chat_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/oarkflow/rtcd/chat"
	"github.com/oarkflow/rtcd/dbx"
	_ "modernc.org/sqlite"
)

var mbg = context.Background()

// The suite runs on SQLite by default; RTCD_TEST_DB=postgres or mysql runs it on
// a real server (the defaults match the server package's tests).
func testDialect() string {
	switch os.Getenv("RTCD_TEST_DB") {
	case "postgres", "mysql":
		return os.Getenv("RTCD_TEST_DB")
	}
	return "sqlite"
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func mlsStore(t testing.TB) *chat.Store { return mlsStoreAt(t, nil) }

func mlsStoreAt(t testing.TB, now func() time.Time) *chat.Store {
	t.Helper()
	d := testDialect()
	var db *sql.DB
	if d == "sqlite" {
		var err error
		db, err = sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "m.db")+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
		if err != nil {
			t.Fatal(err)
		}
	} else {
		sum := sha256.Sum256([]byte(t.TempDir()))
		name := "c" + hex.EncodeToString(sum[:6])
		drv, admin, user := "pgx", envOr("RTCD_PG_DSN", "postgres://postgres:pw@localhost:55432/postgres?sslmode=disable"), envOr("RTCD_PG_BASE", "postgres://postgres:pw@localhost:55432/")+name+"?sslmode=disable"
		if d == "mysql" {
			drv, admin, user = "mysql", envOr("RTCD_MYSQL_DSN", "root:pw@tcp(localhost:53306)/"), envOr("RTCD_MYSQL_BASE", "root:pw@tcp(localhost:53306)/")+name
		}
		a, err := sql.Open(drv, admin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Exec("CREATE DATABASE " + name); err != nil {
			t.Fatalf("create database: %v", err)
		}
		t.Cleanup(func() {
			if d == "postgres" {
				_, _ = a.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
			} else {
				_, _ = a.Exec("DROP DATABASE IF EXISTS " + name)
			}
			a.Close()
		})
		if db, err = sql.Open(drv, user); err != nil {
			t.Fatal(err)
		}
	}
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { db.Close() })
	s, err := chat.Open(mbg, db, chat.Options{Dialect: d, Rebind: dbx.Rebind(d), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// b64 makes an opaque payload; the service never decodes beyond checking it is base64url.
func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func newGroup(t testing.TB, s *chat.Store, conv string) {
	t.Helper()
	if _, err := s.CreateMLSGroup(mbg, "t", conv, b64("gid-"+conv), 1, ""); err != nil {
		t.Fatal(err)
	}
}

func TestKeyPackagesAreSingleUseWithALastResort(t *testing.T) {
	s := mlsStore(t)
	kps := []chat.KPIn{{KP: b64("kp1")}, {KP: b64("kp2")}, {KP: b64("last"), LastResort: true}}
	if n, err := s.PutKeyPackages(mbg, "t", "bob", "d1", kps); err != nil || n != 3 {
		t.Fatalf("put: %d %v", n, err)
	}
	if n, err := s.PutKeyPackages(mbg, "t", "bob", "d1", kps[:1]); err != nil || n != 0 {
		t.Fatalf("the same package again adds nothing: %d %v", n, err)
	}
	if av, lr, _ := s.KeyPackageCount(mbg, "t", "bob", "d1"); av != 2 || !lr {
		t.Fatalf("count: %d %v", av, lr)
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		got, missing, err := s.ClaimKeyPackages(mbg, "t", []string{"bob", "nobody"})
		if err != nil || len(got) != 1 || got[0].LastResort || len(missing) != 1 || missing[0] != "nobody" {
			t.Fatalf("claim %d: %+v %v %v", i, got, missing, err)
		}
		if seen[got[0].KP] {
			t.Fatalf("a single-use package was handed out twice: %s", got[0].KP)
		}
		seen[got[0].KP] = true
	}
	// Used up: the last-resort package is given, and it is given again.
	for i := 0; i < 3; i++ {
		got, _, err := s.ClaimKeyPackages(mbg, "t", []string{"bob"})
		if err != nil || len(got) != 1 || !got[0].LastResort || got[0].KP != b64("last") {
			t.Fatalf("last resort %d: %+v %v", i, got, err)
		}
	}
	// A new last-resort package replaces the old one.
	if _, err := s.PutKeyPackages(mbg, "t", "bob", "d1", []chat.KPIn{{KP: b64("last2"), LastResort: true}}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.ClaimKeyPackages(mbg, "t", []string{"bob"}); len(got) != 1 || got[0].KP != b64("last2") {
		t.Fatalf("replaced last resort: %+v", got)
	}
	if _, err := s.PutKeyPackages(mbg, "t", "bob", "d1", []chat.KPIn{{KP: "not base64 !!"}}); !errors.Is(err, chat.ErrInvalid) {
		t.Fatalf("garbage is refused: %v", err)
	}
}

func TestEveryDeviceOfAUserIsGivenAPackageAndARevokedOneIsNot(t *testing.T) {
	s := mlsStore(t)
	for _, d := range []string{"phone", "laptop", "old"} {
		if _, err := s.PutKeyPackages(mbg, "t", "bob", d, []chat.KPIn{{KP: b64("kp-" + d)}, {KP: b64("lr-" + d), LastResort: true}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.PublishDevice(mbg, "t", "bob", "old", "pub", "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(mbg, "t", "bob", "old"); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.ClaimKeyPackages(mbg, "t", []string{"bob"})
	if err != nil || len(got) != 2 {
		t.Fatalf("two live devices get one each, the revoked one none: %+v %v", got, err)
	}
	if _, err := s.PutKeyPackages(mbg, "t", "bob", "old", []chat.KPIn{{KP: b64("again")}}); !errors.Is(err, chat.ErrRevoked) {
		t.Fatalf("a revoked device cannot publish: %v", err)
	}
}

func TestOneCommitWinsAnEpochAndTheLosersAreToldTheEpoch(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c1")
	const racers = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	var won, lost int
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c1", By: "ada", ByDevice: "d1", Epoch: 1, ID: fmt.Sprintf("c%d", i), Body: b64(fmt.Sprintf("commit-%d", i))}, []string{"ada"})
			mu.Lock()
			defer mu.Unlock()
			var ec *chat.EpochConflict
			switch {
			case err == nil:
				won++
			case errors.As(err, &ec) && ec.Current == 1 && errors.Is(err, chat.ErrEpochConflict):
				lost++
			default:
				t.Errorf("racer %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if won != 1 || lost != racers-1 {
		t.Fatalf("won=%d lost=%d", won, lost)
	}
	hs, _, _ := s.Sync(mbg, "t", "c1", "ada", "d1", 0, 100)
	if len(hs) != 1 || hs[0].Kind != chat.KindCommit || hs[0].Epoch != 1 {
		t.Fatalf("exactly one commit is stored: %+v", hs)
	}
	g, _ := s.MLSGroup(mbg, "t", "c1")
	if g.Epoch != 1 || g.Seq != 1 {
		t.Fatalf("group: %+v", g)
	}
	// Skipping an epoch is a conflict too, never a gap.
	if _, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c1", By: "ada", ByDevice: "d1", Epoch: 3, ID: "skip", Body: b64("x")}, []string{"ada"}); !errors.Is(err, chat.ErrEpochConflict) {
		t.Fatalf("skipped epoch: %v", err)
	}
}

func TestACommitRetriedAfterALostAnswerFindsItself(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	in := chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: 1, ID: "same", Body: b64("x")}
	first, err := s.Commit(mbg, in, []string{"ada"})
	if err != nil || first.Duplicate {
		t.Fatalf("first: %+v %v", first, err)
	}
	again, err := s.Commit(mbg, in, []string{"ada"})
	if err != nil || !again.Duplicate || again.Seq != first.Seq {
		t.Fatalf("a retry returns the stored commit: %+v %v", again, err)
	}
	// Someone else's commit with the same id is not a retry.
	in.By = "bob"
	if _, err := s.Commit(mbg, in, []string{"ada", "bob"}); !errors.Is(err, chat.ErrEpochConflict) {
		t.Fatalf("another sender: %v", err)
	}
}

func TestWelcomesTravelWithTheCommitAndReachOnlyTheirDevice(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	members := []string{"ada", "bob", "cy"}
	out, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: 1, ID: "k", Body: b64("commit"),
		GroupInfo: b64("groupinfo-1"),
		Welcomes:  []chat.Welcome{{User: "bob", Device: "phone", W: b64("w-bob-phone")}, {User: "bob", Device: "laptop", W: b64("w-bob-laptop")}, {User: "cy", Device: "d1", W: b64("w-cy")}}}, members)
	if err != nil || out.Seq != 1 || len(out.Welcomed) != 3 {
		t.Fatalf("commit: %+v %v", out, err)
	}
	g, _ := s.MLSGroup(mbg, "t", "c")
	if g.Seq != 4 || g.GroupInfo != b64("groupinfo-1") || g.GroupInfoEpoch != 1 {
		t.Fatalf("one number for the commit and one for each welcome; group info kept once: %+v", g)
	}
	read := func(user, dev string) (kinds []string, bodies []string) {
		hs, _, err := s.Sync(mbg, "t", "c", user, dev, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hs {
			kinds, bodies = append(kinds, h.Kind), append(bodies, h.Body)
		}
		return
	}
	if k, b := read("ada", "d1"); len(k) != 1 || k[0] != chat.KindCommit || b[0] != b64("commit") {
		t.Fatalf("ada sees the commit only: %v", k)
	}
	if k, b := read("bob", "phone"); len(k) != 2 || k[1] != chat.KindWelcome || b[1] != b64("w-bob-phone") {
		t.Fatalf("bob's phone: %v %v", k, b)
	}
	if _, b := read("bob", "laptop"); len(b) != 2 || b[1] != b64("w-bob-laptop") {
		t.Fatalf("bob's laptop gets its own: %v", b)
	}
	if k, _ := read("bob", "tablet"); len(k) != 1 {
		t.Fatalf("a device nobody welcomed gets no welcome: %v", k)
	}
	if k, b := read("cy", "d1"); len(k) != 2 || b[1] != b64("w-cy") {
		t.Fatalf("cy: %v", k)
	}
	// A welcome for someone who is not in the conversation is refused, and nothing is stored.
	_, err = s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: 2, ID: "bad", Body: b64("c2"),
		Welcomes: []chat.Welcome{{User: "eve", Device: "d1", W: b64("w")}}}, members)
	if !errors.Is(err, chat.ErrInvalid) {
		t.Fatalf("welcome for a stranger: %v", err)
	}
	if g, _ := s.MLSGroup(mbg, "t", "c"); g.Epoch != 1 {
		t.Fatalf("a refused commit moved the group: %+v", g)
	}
}

func TestSyncPagesInOrder(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	for e := int64(1); e <= 7; e++ {
		if _, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: e, ID: fmt.Sprint("k", e), Body: b64(fmt.Sprint("c", e))}, []string{"ada"}); err != nil {
			t.Fatal(err)
		}
	}
	var after int64
	var epochs []int64
	for {
		page, more, err := s.Sync(mbg, "t", "c", "ada", "d1", after, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range page {
			epochs = append(epochs, h.Epoch)
			after = h.Seq
		}
		if !more {
			break
		}
	}
	if fmt.Sprint(epochs) != "[1 2 3 4 5 6 7]" {
		t.Fatalf("order: %v", epochs)
	}
}

func TestSomeoneRemovedFromTheRosterFencesTheGroupUntilACommitRemovesThem(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	commit := func(epoch int64, removed ...string) chat.CommitOut {
		t.Helper()
		out, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: epoch, ID: fmt.Sprint("k", epoch), Body: b64("c"), Removed: removed}, []string{"ada", "bob"})
		if err != nil {
			t.Fatalf("epoch %d: %v", epoch, err)
		}
		return out
	}
	commit(1)
	if st, _ := s.State(mbg, "t", "c"); !st.MLS || st.Rekey || st.Epoch != 1 {
		t.Fatalf("state: %+v", st)
	}
	// eve and fay are taken out of the roster.
	if isMLS, err := s.RemovedFromRoster(mbg, "t", "c", []string{"eve", "fay"}); err != nil || !isMLS {
		t.Fatalf("removed: %v %v", isMLS, err)
	}
	if flagged, _ := s.NeedRekey(mbg, "t", []string{"c"}); len(flagged) != 1 {
		t.Fatalf("an MLS group at any epoch is fenced: %v", flagged)
	}
	g, _ := s.MLSGroup(mbg, "t", "c")
	if !g.Rekey || fmt.Sprint(g.Pending) != "[eve fay]" {
		t.Fatalf("group: %+v", g)
	}
	// A commit that removes only one of them leaves the fence up.
	if out := commit(2, "eve"); !out.Rekey {
		t.Fatalf("one of two removed: %+v", out)
	}
	if st, _ := s.Fresh(mbg, "t", "c"); !st.Rekey {
		t.Fatal("the fence fell early")
	}
	// A commit that claims to remove someone who is still in the roster is refused.
	if _, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: 3, ID: "x", Body: b64("c"), Removed: []string{"bob"}}, []string{"ada", "bob"}); !errors.Is(err, chat.ErrInvalid) {
		t.Fatalf("removing a member: %v", err)
	}
	if out := commit(3, "fay"); out.Rekey {
		t.Fatalf("everyone removed: %+v", out)
	}
	if st, _ := s.Fresh(mbg, "t", "c"); st.Rekey || st.Epoch != 3 {
		t.Fatalf("fence should be down: %+v", st)
	}
}

func TestAConversationHasOneKeyScheme(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	if _, err := s.CreateMLSGroup(mbg, "t", "c", b64("other"), 1, ""); !errors.Is(err, chat.ErrConflict) {
		t.Fatalf("a second group: %v", err)
	}
	if _, err := s.CreateMLSGroup(mbg, "t", "x", b64("gid-c"), 1, ""); !errors.Is(err, chat.ErrConflict) {
		t.Fatalf("a group id used twice: %v", err)
	}
	if _, err := s.CreateMLSGroup(mbg, "t", "y", b64("gid-y"), 0x7777, ""); !errors.Is(err, chat.ErrInvalid) {
		t.Fatalf("an unknown suite: %v", err)
	}
	if _, err := s.CreateMLSGroup(mbg, "t", "z", "not b64 !", 1, ""); !errors.Is(err, chat.ErrInvalid) {
		t.Fatalf("a bad group id: %v", err)
	}
	// A conversation that already runs on per-device epochs cannot become an MLS group.
	if _, _, err := s.PublishDevice(mbg, "t", "ada", "d1", "pub", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(mbg, "t", "old", 1, "ada", "d1", []chat.Wrap{{User: "ada", Device: "d1", W: "w"}}, []string{"ada"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMLSGroup(mbg, "t", "old", b64("gid-old"), 1, ""); !errors.Is(err, chat.ErrConflict) {
		t.Fatalf("epochs to MLS in place: %v", err)
	}
	// And an MLS conversation takes no wrapped-key rotation: Rotate would move its epoch without a commit.
	if err := s.Rotate(mbg, "t", "c", 1, "ada", "d1", []chat.Wrap{{User: "ada", Device: "d1", W: "w"}}, []string{"ada"}); err == nil {
		t.Fatal("Rotate moved an MLS group's epoch")
	}
}

func TestGroupInfoRefreshIsForTheCurrentEpochOnly(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	if _, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: 1, ID: "k", Body: b64("c")}, []string{"ada"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGroupInfo(mbg, "t", "c", 1, b64("gi")); err != nil {
		t.Fatal(err)
	}
	var ec *chat.EpochConflict
	if err := s.PutGroupInfo(mbg, "t", "c", 0, b64("old")); !errors.As(err, &ec) || ec.Current != 1 {
		t.Fatalf("a stale group info: %v", err)
	}
	if g, _ := s.MLSGroup(mbg, "t", "c"); g.GroupInfo != b64("gi") || g.GroupInfoEpoch != 1 {
		t.Fatalf("group: %+v", g)
	}
}

func TestProposalsDoNotMoveTheEpochAndAreIdempotent(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	a, err := s.Propose(mbg, "t", "c", "bob", "d1", "p1", 0, b64("prop"))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := s.Propose(mbg, "t", "c", "bob", "d1", "p1", 0, b64("prop")); err != nil || b != a {
		t.Fatalf("retry: %d %d %v", b, a, err)
	}
	var ec *chat.EpochConflict
	if _, err := s.Propose(mbg, "t", "c", "bob", "d1", "p2", 5, b64("prop")); !errors.As(err, &ec) {
		t.Fatalf("wrong epoch: %v", err)
	}
	if g, _ := s.MLSGroup(mbg, "t", "c"); g.Epoch != 0 {
		t.Fatalf("epoch moved: %+v", g)
	}
}

func TestPurgeRemovesEverythingTheGroupHeld(t *testing.T) {
	s := mlsStore(t)
	newGroup(t, s, "c")
	if _, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: "c", By: "ada", ByDevice: "d1", Epoch: 1, ID: "k", Body: b64("c")}, []string{"ada"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PurgeConv(mbg, "t", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MLSGroup(mbg, "t", "c"); !errors.Is(err, chat.ErrNotFound) {
		t.Fatalf("group survived: %v", err)
	}
	if hs, _, _ := s.Sync(mbg, "t", "c", "ada", "d1", 0, 10); len(hs) != 0 {
		t.Fatalf("handshake survived: %v", hs)
	}
}

// Adding a hundred people is one claim and one commit, however large the group.
func BenchmarkClaimAndCommitAHundredMembers(b *testing.B) {
	s := mlsStore(b)
	users := make([]string, 100)
	for i := range users {
		users[i] = fmt.Sprint("u", i)
		if _, err := s.PutKeyPackages(mbg, "t", users[i], "d", []chat.KPIn{{KP: b64("lr" + users[i]), LastResort: true}}); err != nil {
			b.Fatal(err)
		}
	}
	members := append([]string{"owner"}, users...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conv := fmt.Sprint("c", i)
		if _, err := s.CreateMLSGroup(mbg, "t", conv, b64("g"+conv), 1, ""); err != nil {
			b.Fatal(err)
		}
		got, _, err := s.ClaimKeyPackages(mbg, "t", users)
		if err != nil || len(got) != 100 {
			b.Fatal(err, len(got))
		}
		ws := make([]chat.Welcome, len(got))
		for j, c := range got {
			ws[j] = chat.Welcome{User: c.User, Device: c.Device, W: b64("welcome-" + c.User)}
		}
		if _, err := s.Commit(mbg, chat.CommitIn{Tenant: "t", Conv: conv, By: "owner", ByDevice: "d", Epoch: 1, ID: "k", Body: b64("commit"), Welcomes: ws}, members); err != nil {
			b.Fatal(err)
		}
	}
}

func TestExpiredKeyPackagesAreNeverHandedOutAndAreSwept(t *testing.T) {
	clock := time.Now().UTC()
	s := mlsStoreAt(t, func() time.Time { return clock })
	if _, err := s.PutKeyPackages(mbg, "t", "bob", "d", []chat.KPIn{{KP: b64("short"), TTL: 60}, {KP: b64("lr"), LastResort: true, TTL: 3600}}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Minute)
	got, _, err := s.ClaimKeyPackages(mbg, "t", []string{"bob"})
	if err != nil || len(got) != 1 || !got[0].LastResort {
		t.Fatalf("an expired single-use package was handed out: %+v %v", got, err)
	}
	clock = clock.Add(2 * time.Hour)
	got, missing, _ := s.ClaimKeyPackages(mbg, "t", []string{"bob"})
	if len(got) != 0 || len(missing) != 1 {
		t.Fatalf("an expired last-resort package was handed out: %+v", got)
	}
	if n, err := s.PruneMLS(mbg, 0, 0); err != nil || n != 2 {
		t.Fatalf("sweep removed %d: %v", n, err)
	}
}

func TestADeviceHoldsAtMostAHundredSingleUsePackages(t *testing.T) {
	s := mlsStore(t)
	var batch []chat.KPIn
	for i := 0; i < chat.MaxKeyPackages; i++ {
		batch = append(batch, chat.KPIn{KP: b64(fmt.Sprint("kp", i))})
	}
	if n, err := s.PutKeyPackages(mbg, "t", "bob", "d", batch); err != nil || n != chat.MaxKeyPackages {
		t.Fatalf("fill: %d %v", n, err)
	}
	if _, err := s.PutKeyPackages(mbg, "t", "bob", "d", []chat.KPIn{{KP: b64("one-more")}}); !errors.Is(err, chat.ErrLimit) {
		t.Fatalf("over the cap: %v", err)
	}
	// The last-resort package is outside the cap, and the refused upload left nothing behind.
	if _, err := s.PutKeyPackages(mbg, "t", "bob", "d", []chat.KPIn{{KP: b64("lr"), LastResort: true}}); err != nil {
		t.Fatal(err)
	}
	if av, lr, _ := s.KeyPackageCount(mbg, "t", "bob", "d"); av != chat.MaxKeyPackages || !lr {
		t.Fatalf("count: %d %v", av, lr)
	}
}

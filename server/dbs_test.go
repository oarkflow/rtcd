package server_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// The suite runs on SQLite by default. RTCD_TEST_DB=postgres or mysql runs it on
// a real server instead (RTCD_PG_DSN / RTCD_MYSQL_DSN name an administrative
// connection; the defaults match `docker run` with the ports used in the README).
// Each database is made fresh for the test and dropped afterwards.
var (
	dbMu    sync.Mutex
	dbMade  = map[string]string{}
	dbOwner = map[string]bool{}
)

func dialect() string {
	switch os.Getenv("RTCD_TEST_DB") {
	case "postgres":
		return "postgres"
	case "mysql":
		return "mysql"
	}
	return "sqlite"
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// testDB opens the database called name inside dir. Opening the same dir and
// name again returns another handle on the same database (two nodes).
func testDB(t testing.TB, dir, name string, conns int) *sql.DB {
	t.Helper()
	d := dialect()
	if d == "sqlite" {
		db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, name)+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(conns)
		t.Cleanup(func() { db.Close() })
		return db
	}
	sum := sha256.Sum256([]byte(dir + name))
	db := "t" + hex.EncodeToString(sum[:6])
	adminDSN, drv, userDSN := "", "pgx", ""
	if d == "postgres" {
		adminDSN = env("RTCD_PG_DSN", "postgres://postgres:pw@localhost:55432/postgres?sslmode=disable")
		userDSN = env("RTCD_PG_BASE", "postgres://postgres:pw@localhost:55432/") + db + "?sslmode=disable"
	} else {
		drv = "mysql"
		adminDSN = env("RTCD_MYSQL_DSN", "root:pw@tcp(localhost:53306)/")
		userDSN = env("RTCD_MYSQL_BASE", "root:pw@tcp(localhost:53306)/") + db
	}
	dbMu.Lock()
	first := dbMade[dir+name] == ""
	dbMade[dir+name] = db
	dbMu.Unlock()
	if first {
		admin, err := sql.Open(drv, adminDSN)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec("CREATE DATABASE " + db); err != nil {
			t.Fatalf("create database: %v", err)
		}
		t.Cleanup(func() {
			if d == "postgres" {
				_, _ = admin.Exec("DROP DATABASE IF EXISTS " + db + " WITH (FORCE)")
			} else {
				_, _ = admin.Exec("DROP DATABASE IF EXISTS " + db)
			}
			admin.Close()
		})
	}
	h, err := sql.Open(drv, userDSN)
	if err != nil {
		t.Fatal(err)
	}
	h.SetMaxOpenConns(10)
	t.Cleanup(func() { h.Close() })
	return h
}

// probe watches the test databases on PostgreSQL while a load runs: the most
// statements ever running at the same moment, and how many transactions (every
// statement outside a transaction is one) were committed.
func probe(t testing.TB) (stop func() (maxActive int, xacts int64)) {
	if dialect() != "postgres" {
		return func() (int, int64) { return 0, 0 }
	}
	admin, err := sql.Open("pgx", env("RTCD_PG_DSN", "postgres://postgres:pw@localhost:55432/postgres?sslmode=disable"))
	if err != nil {
		t.Fatal(err)
	}
	dbMu.Lock()
	var names []string
	for _, n := range dbMade {
		names = append(names, "'"+n+"'")
	}
	dbMu.Unlock()
	list := "''"
	if len(names) > 0 {
		list = ""
		for i, n := range names {
			if i > 0 {
				list += ","
			}
			list += n
		}
	}
	count := func() (a int, x int64) {
		_ = admin.QueryRow("SELECT count(*) FROM pg_stat_activity WHERE state='active' AND datname IN (" + list + ") AND pid<>pg_backend_pid() AND query NOT LIKE '%pg_stat%'").Scan(&a)
		_ = admin.QueryRow("SELECT COALESCE(sum(xact_commit+xact_rollback),0)::bigint FROM pg_stat_database WHERE datname IN (" + list + ")").Scan(&x)
		return
	}
	_, base := count()
	done, res := make(chan struct{}), make(chan int)
	go func() {
		max := 0
		for {
			select {
			case <-done:
				res <- max
				return
			default:
			}
			if a, _ := count(); a > max {
				max = a
			}
		}
	}()
	return func() (int, int64) {
		close(done)
		max := <-res
		time.Sleep(300 * time.Millisecond) // stats are reported with a short delay
		_, x := count()
		admin.Close()
		return max, x - base
	}
}

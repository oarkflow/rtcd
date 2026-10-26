// Package open opens a database for rtcd: SQLite, PostgreSQL or MySQL. It links
// the drivers, so only programs (not the libraries) import it.
package open

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Pool bounds how many statements one node runs against the database at
// once. SQLite has a single writer, so it gets one connection; a server database
// gets MaxOpen (default 20), which is the most queries this node ever has in
// flight, whatever the load. With several nodes, size it so nodes x MaxOpen stays
// under the database's own connection limit.
type Pool struct {
	MaxOpen, MaxIdle int
	MaxLifetime      time.Duration
}

// DB opens a database of the given driver (sqlite, postgres or mysql) and
// returns it with the dialect the stores should speak.
func DB(driver, dsn string, p Pool) (*sql.DB, string, error) {
	var name, dialect string
	switch driver {
	case "", "sqlite":
		name, dialect = "sqlite", "sqlite"
	case "postgres", "postgresql":
		name, dialect = "pgx", "postgres"
	case "mysql", "mariadb":
		name, dialect = "mysql", "mysql"
	default:
		return nil, "", fmt.Errorf("database driver %q: use sqlite, postgres or mysql", driver)
	}
	db, err := sql.Open(name, dsn)
	if err != nil {
		return nil, "", err
	}
	if dialect == "sqlite" {
		db.SetMaxOpenConns(1)
		return db, dialect, nil
	}
	if p.MaxOpen <= 0 {
		p.MaxOpen = 20
	}
	if p.MaxIdle <= 0 || p.MaxIdle > p.MaxOpen {
		p.MaxIdle = p.MaxOpen
	}
	if p.MaxLifetime <= 0 {
		p.MaxLifetime = 30 * time.Minute
	}
	db.SetMaxOpenConns(p.MaxOpen)
	db.SetMaxIdleConns(p.MaxIdle)
	db.SetConnMaxLifetime(p.MaxLifetime)
	return db, dialect, nil
}

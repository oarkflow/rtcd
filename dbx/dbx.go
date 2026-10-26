// Package dbx is what the stores share to run on SQLite, PostgreSQL and MySQL.
//
// Queries are written with numbered placeholders ($1, $2, ...), each used once
// and in order. Rebind turns them into what the database speaks.
package dbx

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
)

var numbered = regexp.MustCompile(`\$\d+`)

// Rebind returns the function that adapts a query to the dialect.
func Rebind(dialect string) func(string) string {
	if dialect == "mysql" {
		return func(q string) string { return numbered.ReplaceAllString(q, "?") }
	}
	return func(q string) string { return q } // sqlite and postgres take $n as written
}

// DDL runs a schema statement. MySQL has no CREATE INDEX IF NOT EXISTS, so there
// the clause is dropped and a duplicate index is not an error.
func DDL(ctx context.Context, db *sql.DB, dialect, q string) error {
	if dialect != "mysql" {
		_, err := db.ExecContext(ctx, q)
		return err
	}
	isIndex := strings.Contains(q, "INDEX IF NOT EXISTS")
	if isIndex {
		q = strings.Replace(q, "INDEX IF NOT EXISTS", "INDEX", 1)
	}
	_, err := db.ExecContext(ctx, q)
	if err != nil && isIndex && strings.Contains(err.Error(), "Duplicate key name") {
		return nil
	}
	return err
}

// Serial is the column type of an auto-numbered primary key.
func Serial(dialect string) string {
	switch dialect {
	case "postgres":
		return "BIGSERIAL PRIMARY KEY"
	case "mysql":
		return "BIGINT AUTO_INCREMENT PRIMARY KEY"
	}
	return "INTEGER PRIMARY KEY AUTOINCREMENT"
}

// IsDuplicate reports whether err is a unique-key violation on any dialect.
func IsDuplicate(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "unique constraint") || strings.Contains(m, "duplicate key") ||
		strings.Contains(m, "duplicate entry") || strings.Contains(m, "23505") || strings.Contains(m, "1062")
}

// IsRetryable reports a deadlock or serialization failure: the statement lost a
// race with another and nothing was written, so trying again is right.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "deadlock") || strings.Contains(m, "40p01") || strings.Contains(m, "40001") || strings.Contains(m, "1213") || strings.Contains(m, "database is locked")
}

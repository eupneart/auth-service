// Command migrate applies the SQL files in migrations/ to the configured
// database, recording every applied version so each migration runs exactly once.
// Re-running is not enough on its own: several migrations use
// ALTER TABLE ... ADD CONSTRAINT, which Postgres rejects the second time.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/eupneart/auth-service/internal/db"
	"github.com/eupneart/auth-service/pkg/env"

	_ "github.com/jackc/pgx/v4/stdlib"
)

const createSchemaMigrations = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

type migration struct {
	version int64
	name    string
	path    string
}

func main() {
	dir := flag.String("path", "migrations", "directory holding the migration files")
	flag.Parse()

	command := flag.Arg(0)
	if command == "" {
		command = "up"
	}

	cfg := env.LoadEnv()

	// ConnectToDB logs and returns nil rather than an error when Postgres never
	// answers, so an unchecked result would panic on the first query.
	conn := db.ConnectToDB(cfg)
	if conn == nil {
		log.Fatal("could not connect to the database")
	}
	defer conn.Close()

	if _, err := conn.Exec(createSchemaMigrations); err != nil {
		log.Fatalf("creating schema_migrations: %v", err)
	}

	var err error
	switch command {
	case "up":
		err = migrateUp(conn, *dir)
	case "down":
		err = migrateDown(conn, *dir)
	default:
		log.Fatalf("unknown command %q: expected \"up\" or \"down\"", command)
	}

	if err != nil {
		log.Fatalf("migrate %s: %v", command, err)
	}
}

func migrateUp(conn *sql.DB, dir string) error {
	migrations, err := loadMigrations(dir, ".up.sql")
	if err != nil {
		return err
	}

	applied, err := appliedVersions(conn)
	if err != nil {
		return err
	}

	count := 0
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}

		if err := apply(conn, m, `INSERT INTO schema_migrations (version) VALUES ($1)`); err != nil {
			return fmt.Errorf("applying %s: %w", m.name, err)
		}

		log.Printf("applied %s", m.name)
		count++
	}

	if count == 0 {
		log.Println("no pending migrations")
	}

	return nil
}

// migrateDown rolls back only the most recently applied migration, so an
// accidental invocation costs one version rather than the whole schema.
func migrateDown(conn *sql.DB, dir string) error {
	var version int64
	err := conn.QueryRow(`SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&version)
	if err == sql.ErrNoRows {
		log.Println("nothing to roll back")
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading last applied version: %w", err)
	}

	migrations, err := loadMigrations(dir, ".down.sql")
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if m.version != version {
			continue
		}

		if err := apply(conn, m, `DELETE FROM schema_migrations WHERE version = $1`); err != nil {
			return fmt.Errorf("rolling back %s: %w", m.name, err)
		}

		log.Printf("rolled back %s", m.name)
		return nil
	}

	return fmt.Errorf("no down migration found for applied version %d", version)
}

// ========================= Helper functions ============================

// apply runs a migration and its bookkeeping statement in one transaction, so a
// failure leaves neither the schema change nor a version row claiming it landed.
func apply(conn *sql.DB, m migration, bookkeeping string) error {
	statements, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}

	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Passing no arguments makes pgx use the simple protocol, which is what
	// allows a file of several semicolon-separated statements in one call.
	if _, err := tx.Exec(string(statements)); err != nil {
		return err
	}

	if _, err := tx.Exec(bookkeeping, m.version); err != nil {
		return err
	}

	return tx.Commit()
}

// loadMigrations returns the migrations with the given suffix ordered by the
// numeric prefix of their filename. Ordering by name instead would run 010
// before 002.
func loadMigrations(dir, suffix string) ([]migration, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*"+suffix))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no %s files found in %s", suffix, dir)
	}

	migrations := make([]migration, 0, len(paths))
	for _, path := range paths {
		name := filepath.Base(path)

		prefix, _, found := strings.Cut(name, "_")
		if !found {
			return nil, fmt.Errorf("migration %s has no version prefix", name)
		}

		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("migration %s has an invalid version prefix: %w", name, err)
		}

		migrations = append(migrations, migration{version: version, name: name, path: path})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	return migrations, nil
}

func appliedVersions(conn *sql.DB) (map[int64]bool, error) {
	rows, err := conn.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("reading applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int64]bool)
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}

	return applied, rows.Err()
}

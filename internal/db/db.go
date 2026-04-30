package db

import (
	"database/sql"
	"log"
	"time"

	"github.com/eupneart/auth-service/pkg/env"
)

const maxRetries = 10

func ConnectToDB(cfg *env.EnvConfig) *sql.DB {
	dsn := cfg.ToDSN() 

	for retries := 0; retries < maxRetries; retries++ {
		connection, err := openDB(dsn)
		if err == nil {
			log.Println("Connected to Postgres!")
			return connection
    }

    log.Printf("Postgres not ready, attempt %d/%d: %v", retries+1, maxRetries, err)
    time.Sleep(time.Duration(retries+1) * time.Second)
  }

  log.Printf("failed to connect to Postgres after %d attempts", maxRetries)
  return nil 
}

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	// Configure connection pooling
	// MaxOpenConns: Maximum number of open connections to the database
	// Set to 25 to handle typical load without overwhelming PostgreSQL
	db.SetMaxOpenConns(25)

	// MaxIdleConns: Number of connections to keep idle in the pool
	// Set to 5 to maintain a ready pool for quick reuse
	db.SetMaxIdleConns(5)

	// ConnMaxLifetime: Maximum amount of time a connection may be reused
	// Set to 5 minutes to prevent stale connections
	db.SetConnMaxLifetime(5 * time.Minute)

	// ConnMaxIdleTime: Maximum amount of time a connection may be idle
	// Set to 2 minutes to clean up unused connections
	db.SetConnMaxIdleTime(2 * time.Minute)

	return db, nil
}

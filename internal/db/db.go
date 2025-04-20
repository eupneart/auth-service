package db

import (
	"database/sql"
	"log"
	"os"
	"time"
)

const maxRetries = 10

func ConnectToDB() *sql.DB {
	dsn := os.Getenv("DSN")

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

	return db, nil
}

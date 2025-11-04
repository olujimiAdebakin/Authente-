package database


import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" 
	// _ "github.com/go-sql-driver/mysql"
	// _ "modernc.org/sqlite"
)

// DB wraps the sql.DB connection pool
type DB struct {
	*sql.DB
}

// New creates a new database connection pool
func New(connectionString string) (*DB, error) {
	db, err := sql.Open("postgres", connectionString) 
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for optimal performance
	db.SetMaxOpenConns(25)                    // Maximum open connections
	db.SetMaxIdleConns(10)                    // Maximum idle connections  
	db.SetConnMaxLifetime(30 * time.Minute)   // Maximum connection lifetime
	db.SetConnMaxIdleTime(5 * time.Minute)    // Maximum idle time

	// Verify connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{db}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	if db.DB != nil {
		return db.DB.Close()
	}
	return nil
}

// WithTx executes a function within a database transaction
func (db *DB) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // re-panic after rollback
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	return tx.Commit()
}

// HealthCheck checks if database is responsive
func (db *DB) HealthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}
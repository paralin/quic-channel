package db

import (
	"time"

	"github.com/boltdb/bolt"
)

// BoltDB backed database.
type DB struct {
	DB *bolt.DB
}

// OpenDB opens the database.
func OpenDB(dbPath string) (*DB, error) {
	res := &DB{}
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	res.DB = db
	res.ensureBuckets()

	return res, nil
}

// Close closes the database.
func (db *DB) Close() error {
	return db.DB.Close()
}

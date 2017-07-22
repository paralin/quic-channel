package db

import (
	"github.com/boltdb/bolt"
)

// GetOrEnsureBucket returns a bucket and if possible, creates it if it does not exist.
func GetOrEnsureBucket(tx *bolt.Tx, key []byte) *bolt.Bucket {
	if tx.Writable() {
		b, _ := tx.CreateBucketIfNotExists(key)
		return b
	}
	return tx.Bucket(key)
}

package db

import (
	"github.com/boltdb/bolt"
)

// GetPeerBucket returns the peer storage bucket.
func (kvg *DB) GetPeerBucket(tx *bolt.Tx) *bolt.Bucket {
	return GetOrEnsureBucket(tx, []byte("peers"))
}

func (kvg *DB) ensureBuckets() error {
	return kvg.DB.Update(func(tx *bolt.Tx) error {
		kvg.GetPeerBucket(tx)
		return nil
	})
}

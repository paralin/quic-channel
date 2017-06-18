package signature

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

// NewDataHash hashes some data and packages it in a DataHash.
func NewDataHash(hashType ESignedMessageHash, data []byte) (*DataHash, error) {
	dh := &DataHash{HashType: hashType}
	d, _, err := HashData(hashType, data)
	if err != nil {
		return nil, err
	}
	dh.Hash = d
	return dh, nil
}

// Verify verifies the DataHash
func (dh *DataHash) Verify(data []byte) error {
	d, _, err := HashData(dh.HashType, data)
	if err != nil {
		return err
	}

	if bytes.Compare(d, dh.Hash) != 0 {
		return errors.New("Hashes do not match.")
	}

	return nil
}

// HashData hashes data with a given hashType.
func HashData(hashType ESignedMessageHash, data []byte) (hashed []byte, hft crypto.Hash, err error) {
	var hf hash.Hash
	hf, hft, err = LookupHashFunction(hashType)
	if err != nil {
		return
	}

	_, err = hf.Write(data)
	if err != nil {
		return
	}

	hashed = hf.Sum(nil)
	return
}

// HashData uses a hash type to hash a message.
func LookupHashFunction(hashType ESignedMessageHash) (hash.Hash, crypto.Hash, error) {
	switch hashType {
	case ESignedMessageHash_HASH_SHA256:
		return sha256.New(), crypto.SHA256, nil
	default:
		return nil, crypto.Hash(0), fmt.Errorf("Unknown hash kind %s\n", hashType.String())
	}
}

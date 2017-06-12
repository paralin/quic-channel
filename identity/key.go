package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

// PublicKeyHash is the hash of a public key.
type PublicKeyHash [sha256.Size]byte

// MarshalPublicKey encodes one or more public keys to pem format.
func MarshalPublicKey(pkeys ...interface{}) ([]byte, error) {
	var result bytes.Buffer

	for _, key := range pkeys {
		data, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

		result.Write(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: data,
		}))
	}

	return result.Bytes(), nil
}

// HashPublicKey hashes a public key.
func HashPublicKey(pkey interface{}) (PublicKeyHash, error) {
	data, err := MarshalPublicKey(pkey)
	return sha256.Sum256(data), err
}

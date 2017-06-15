package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func generatePublicKeyHash() PublicKeyHash {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	hash, err := HashPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return hash
}

func TestMarshalHashIdentifier(t *testing.T) {
	hash := generatePublicKeyHash()
	t.Logf("Generated hash: %s", hash.MarshalHashIdentifier())
}

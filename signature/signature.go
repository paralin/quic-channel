package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/golang/protobuf/proto"
)

// NewSignedMessage builds and signs a message in one go.
func NewSignedMessage(hashType ESignedMessageHash, saltLen int, message proto.Message, privateKey *rsa.PrivateKey) (*SignedMessage, error) {
	data, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}

	result := &SignedMessage{Message: data, SignatureSalt: make([]byte, saltLen), HashType: hashType}

	if err := result.GenerateSalt(saltLen); err != nil {
		return nil, err
	}

	if err := result.Sign(privateKey); err != nil {
		return nil, err
	}

	return result, nil
}

// GenerateSalt generates and fills the salt with a length.
func (m *SignedMessage) GenerateSalt(saltLen int) error {
	if saltLen < 1 {
		m.SignatureSalt = nil
		return nil
	}

	m.SignatureSalt = make([]byte, saltLen)
	_, err := rand.Read(m.SignatureSalt)
	return err
}

// Unmarshal decodes the message and verifies the signature.
func (m *SignedMessage) Unmarshal(target proto.Message, publicKey *rsa.PublicKey) error {
	if err := m.VerifySignature(publicKey); err != nil {
		return err
	}

	return proto.Unmarshal(m.Message, target)
}

// VerifySignature verifies the signature.
func (m *SignedMessage) VerifySignature(publicKey *rsa.PublicKey) error {
	hash, hashKind, err := m.Hash()
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(publicKey, hashKind, hash, m.Signature)
}

// Hash hashes the message and returns the hash.
func (m *SignedMessage) Hash() ([]byte, crypto.Hash, error) {
	hf, hfk, err := LookupHashFunction(m.HashType)
	if err != nil {
		return nil, crypto.Hash(0), err
	}

	hf.Write(m.Message)
	if len(m.SignatureSalt) > 0 {
		hf.Write(m.SignatureSalt)
	}
	hash := hf.Sum(nil)
	return hash[:], hfk, nil
}

// Sign signs the message.
func (m *SignedMessage) Sign(privateKey *rsa.PrivateKey) error {
	hash, hashKind, err := m.Hash()
	if err != nil {
		return err
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hashKind, hash[:])
	if err != nil {
		return err
	}
	m.Signature = sig
	return nil
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

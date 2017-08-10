package signature

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/golang/protobuf/proto"
)

// NewEncryptedMessage builds and encrypts a message in one go.
func NewEncryptedMessage(
	hashType ESignedMessageHash,
	message proto.Message,
	targetPubKey *rsa.PublicKey,
) (*EncryptedMessage, error) {
	data, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}

	result := &EncryptedMessage{
		HashType: hashType,
	}

	if err := result.Encrypt(targetPubKey, data); err != nil {
		return nil, err
	}

	return result, nil
}

// Encrypt overwrites the data in the message by encrypting new data.
func (e *EncryptedMessage) Encrypt(pubKey *rsa.PublicKey, data []byte) error {
	hf, _, err := LookupHashFunction(e.HashType)
	if err != nil {
		return err
	}

	encData, err := rsa.EncryptOAEP(hf, rand.Reader, pubKey, data, nil)
	if err != nil {
		return err
	}

	e.CipherText = encData
	return nil
}

// Decrypt decrypts the data in the message.
func (e *EncryptedMessage) Decrypt(privKey *rsa.PrivateKey) ([]byte, error) {
	hf, _, err := LookupHashFunction(e.HashType)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(hf, rand.Reader, privKey, e.GetCipherText(), nil)
}

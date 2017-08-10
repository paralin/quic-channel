package signature

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang/protobuf/proto"
)

func TestEncryptE2E(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	testData := make([]byte, 50)
	rand.Read(testData)

	msg := &DataHash{Hash: testData}
	encMsg, err := NewEncryptedMessage(
		ESignedMessageHash_HASH_SHA256,
		msg,
		&privKey.PublicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	decMsg := &DataHash{}
	decMsgData, err := encMsg.Decrypt(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(decMsgData, decMsg); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(decMsg.Hash, msg.Hash) != 0 {
		t.Fatal("decrypted message did not match")
	}
}

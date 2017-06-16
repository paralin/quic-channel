package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/fuserobotics/quic-channel/testdata"
)

func generatePublicKeyHash() *PublicKeyHash {
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
	ip, err := hash.ToIPv6Addr(testdata.CertificateAuthorityCert())
	if err != nil {
		t.Fatal(err.Error())
	}

	ipString := ip.String()
	expectedClusterSegment := "fdcc:4593:bfc4:cabe"
	t.Logf("Generated IP: %s", ipString)
	if !strings.HasPrefix(ipString, expectedClusterSegment) {
		t.Fatalf("Expected prefix %s for the cluster segment.", expectedClusterSegment)
	}
}

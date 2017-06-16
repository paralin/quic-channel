package identity

import (
	"bytes"
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
	expectedCaHash, err := HashCACertificate(testdata.CertificateAuthorityCert())
	if err != nil {
		t.Fatal(err.Error())
	}

	expectedClusterSegment := "fdcc:4593:bf"
	t.Logf("Generated IP: %s", ipString)
	if !strings.HasPrefix(ipString, expectedClusterSegment) {
		t.Fatalf("Expected prefix %s for the cluster segment.", expectedClusterSegment)
	}

	parsedPublicKey, parsedClusterCert, err := IPv6AddrToPeer(ip)
	if err != nil {
		t.Fatal(err.Error())
	}

	ppkh := (*parsedPublicKey)[:]
	ppkhPartial := (*hash)[:len(ppkh)]
	if bytes.Compare(ppkh, ppkhPartial) != 0 {
		t.Fatalf("Parsed public key hash %v != %v", ppkh, ppkhPartial)
	}

	pcch := (*parsedClusterCert)[:]
	pcchPartial := (*expectedCaHash)[:len(pcch)]
	if bytes.Compare(pcch, pcchPartial) != 0 {
		t.Fatalf("Parsed cluster cert hash %v != %v", pcch, pcchPartial)
	}

	t.Log("Public key hash and cluster cert hash match.")
}

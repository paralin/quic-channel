package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"net"
	"strings"
)

// ipv6AddrPrefix is the prefix for every IPV6 addr in the system.
var ipv6AddrPrefix = []byte{0xfd, 0xcc}

// PublicKeyHash is the hash of a public key.
type PublicKeyHash [sha256.Size]byte

// ClusterCertHash is the hash of the cluster CA cert public key.
type ClusterCertHash [sha256.Size]byte

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
func HashPublicKey(pkey interface{}) (*PublicKeyHash, error) {
	data, err := x509.MarshalPKIXPublicKey(pkey)
	if err != nil {
		return nil, err
	}

	hash := PublicKeyHash(sha256.Sum256(data))
	return &hash, err
}

// MarshalHashIdentifier returns the 8 byte human-readable hash of the public key.
func (h *PublicKeyHash) MarshalHashIdentifier() string {
	return strings.ToLower(string([]rune(base32.StdEncoding.EncodeToString(h[:8]))))
}

// ToIPv6Addr converts the public key hash to a IP address.
func (h *PublicKeyHash) ToIPv6Addr(caCert *x509.Certificate) (net.IP, error) {
	caHash, err := HashCACertificate(caCert)
	if err != nil {
		return nil, err
	}

	ip := net.IP(make([]byte, 16))
	// Prefix + L
	copy(ip, ipv6AddrPrefix)
	// Copy the first 6 bytes of the hash to the global ID and subnet ID.
	copy(ip[2:], caHash[:6])
	// Copy the rest from the hash
	copy(ip[8:], (*h)[:8])

	return ip, nil
}

// HashCACertificate returns a CaCertHash for the purposes of IPv6 address generation.
func HashCACertificate(caCert *x509.Certificate) (*ClusterCertHash, error) {
	// Generate the subnet etc from the ca cert.
	caHash, err := HashPublicKey(caCert.PublicKey)
	if err != nil {
		return nil, err
	}
	h := ClusterCertHash(*caHash)
	return &h, nil
}

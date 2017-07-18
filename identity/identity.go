package identity

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net"

	"github.com/fuserobotics/quic-channel/signature"
)

// ParsedIdentity parses and caches parsed identity data.
type ParsedIdentity struct {
	*Identity
	certs      CertificateChain
	privateKey *rsa.PrivateKey
}

// NewParsedIdentity makes a new parsed identity.
func NewParsedIdentity(ident *Identity) *ParsedIdentity {
	return &ParsedIdentity{Identity: ident}
}

// NewParsedIdentityFromChain creates a new parsed identity from a certificate chain.
func NewParsedIdentityFromChain(certChain CertificateChain) (*ParsedIdentity, error) {
	ident := &ParsedIdentity{Identity: &Identity{}}
	if err := ident.SetCertificateChain(certChain); err != nil {
		return nil, err
	}
	return ident, nil
}

// verifyPrivateKey verifies the private key is still valid.
func (i *ParsedIdentity) verifyPrivateKey() error {
	if i.privateKey == nil {
		return errors.New("Private key is nil.")
	}
	// get the leaf of the cert chain.
	if len(i.certs) < 1 {
		return errors.New("Certificate chain must be set before the private key.")
	}

	leaf := i.certs[0]
	pkey, pkeyValid := leaf.PublicKey.(*rsa.PublicKey)
	if !pkeyValid {
		return errors.New("Certificate public key is not RSA.")
	}

	if !ComparePublicKey(pkey, &i.privateKey.PublicKey) {
		return errors.New("Certificate public key does not match given private key.")
	}

	return nil
}

// CompareTo sees if two parsed identities are equivilent.
func (i *ParsedIdentity) CompareTo(other *ParsedIdentity) bool {
	if other == nil || i == nil {
		return false
	}

	pkh, err := i.HashPublicKey()
	if err != nil {
		return false
	}

	opkh, err := other.HashPublicKey()
	if err != nil {
		return false
	}

	return opkh.MatchesPartialHash((*pkh)[:])
}

// SetPrivateKey sets the private key of this identity.
func (i *ParsedIdentity) SetPrivateKey(key *rsa.PrivateKey) (err error) {
	i.privateKey = key

	defer func() {
		if err != nil {
			i.privateKey = nil
		}
	}()

	return i.verifyPrivateKey()
}

// GetPrivateKey returns the RSA private key, if set.
func (i *ParsedIdentity) GetPrivateKey() *rsa.PrivateKey {
	return i.privateKey
}

// HashPublicKey hashes the public key of the identity.
func (i *ParsedIdentity) HashPublicKey() (*PublicKeyHash, error) {
	chain, err := i.ParseCertificates()
	if err != nil {
		return nil, err
	}

	return chain.HashPublicKey()
}

// ParseCertificates parses the certificates or returns the cached data.
func (i *ParsedIdentity) ParseCertificates() (CertificateChain, error) {
	if len(i.certs) == len(i.CertAsn1) {
		return i.certs, nil
	}

	certss, err := i.Identity.ParseCertificates()
	certs := CertificateChain(certss)
	i.certs = certs
	return certs, err
}

// SetCertificateChain sets the cert chain, leaf first.
func (i *ParsedIdentity) SetCertificateChain(certs CertificateChain) error {
	if len(certs) < 1 {
		return errors.New("Certificate chain is empty.")
	}

	result := make([][]byte, len(certs))
	for i, cert := range certs {
		result[i] = cert.Raw
	}
	i.certs = certs
	i.Identity.CertAsn1 = result

	if i.verifyPrivateKey() != nil {
		i.privateKey = nil
	}

	return nil
}

// ParseCertificates parses the certificates.
func (i *Identity) ParseCertificates() ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, len(i.CertAsn1))
	for i, certData := range i.CertAsn1 {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, err
		}
		result[i] = cert
	}
	return result, nil
}

// VerifyMessage verifies a signed message.
func (i *ParsedIdentity) VerifyMessage(ca *x509.Certificate, sig *signature.SignedMessage) error {
	certsSlice, err := i.ParseCertificates()
	if err != nil {
		return err
	}

	certs := CertificateChain(certsSlice)
	return certs.Validate(ca)
}

// ToIPv6Addr generates an IP address from the identity.
func (i *ParsedIdentity) ToIPv6Addr(ca *x509.Certificate) (net.IP, error) {
	pkh, err := i.HashPublicKey()
	if err != nil {
		return nil, err
	}

	return pkh.ToIPv6Addr(ca)
}

// ToPartialPeerIdentifier generates a PeerIdentifier from this identity.
func (i *ParsedIdentity) ToPartialPeerIdentifier() (*PeerIdentifier, error) {
	pkh, err := i.HashPublicKey()
	if err != nil {
		return nil, err
	}
	return &PeerIdentifier{MatchPublicKey: (*pkh)[:10]}, nil
}

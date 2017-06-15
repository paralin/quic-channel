package identity

import (
	"crypto/x509"

	"github.com/fuserobotics/quic-channel/signature"
)

// ParsedIdentity parses and caches parsed identity data.
type ParsedIdentity struct {
	*Identity
	certs CertificateChain
}

// NewParsedIdentity makes a new parsed identity.
func NewParsedIdentity(ident *Identity) *ParsedIdentity {
	return &ParsedIdentity{Identity: ident}
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
	if len(i.certs) == len(i.CertPem) {
		return i.certs, nil
	}

	certss, err := i.Identity.ParseCertificates()
	certs := CertificateChain(certss)
	i.certs = certs
	return certs, err
}

// SetCertificateChain sets the cert chain, leaf first.
func (i *ParsedIdentity) SetCertificateChain(certs CertificateChain) error {
	result := make([][]byte, len(certs))
	for i, cert := range certs {
		result[i] = cert.Raw
	}
	i.certs = certs
	i.Identity.CertPem = result
	return nil
}

// ParseCertificates parses the certificates.
func (i *Identity) ParseCertificates() ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, len(i.CertPem))
	for i, certData := range i.CertPem {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, err
		}
		result[i] = cert
	}
	return result, nil
}

// VerifyMessage verifies a signed message.
func (i *ParsedIdentity) VerifyMessage(ca *x509.CertPool, sig *signature.SignedMessage) error {
	certsSlice, err := i.ParseCertificates()
	if err != nil {
		return err
	}

	certs := CertificateChain(certsSlice)
	return certs.Validate(ca)
}

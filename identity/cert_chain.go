package identity

import (
	"errors"
	"time"

	"crypto/x509"
)

// CertificateChain is a chain of certificates, leaf first.
type CertificateChain []*x509.Certificate

// Validate validates the chain with a given CA.
func (c CertificateChain) Validate(ca *x509.Certificate) error {
	if len(c) == 0 {
		return errors.New("Cannot validate an empty certificate chain.")
	}

	intermediatePool := x509.NewCertPool()
	for _, inter := range c[1:] {
		intermediatePool.AddCert(inter)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	_, err := c[0].Verify(x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Roots:         caPool,
		Intermediates: intermediatePool,
	})
	return err
}

// HashPublicKey hashes the public key of the leaf (identity)
func (c CertificateChain) HashPublicKey() (*PublicKeyHash, error) {
	if len(c) == 0 {
		return nil, errors.New("Cannot hash public key of empty chain.")
	}

	return HashPublicKey(c[0].PublicKey)
}

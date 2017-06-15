package identity

import (
	"errors"
	"time"

	"crypto/x509"
)

// CertificateChain is a chain of certificates, leaf first.
type CertificateChain []*x509.Certificate

// Validate validates the chain with a given CA.
func (c CertificateChain) Validate(ca *x509.CertPool) error {
	if len(c) == 0 {
		return errors.New("Cannot validate an empty certificate chain.")
	}

	intermediatePool := x509.NewCertPool()
	for _, inter := range c[1:] {
		intermediatePool.AddCert(inter)
	}

	_, err := c[0].Verify(x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Roots:         ca,
		Intermediates: intermediatePool,
	})
	return err
}

// HashPublicKey hashes the public key of the leaf (identity)
func (c CertificateChain) HashPublicKey() (*PublicKeyHash, error) {
	if len(c) == 0 {
		return nil, errors.New("Cannot hash public key of empty chain.")
	}

	pk, err := HashPublicKey(c[0].PublicKey)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

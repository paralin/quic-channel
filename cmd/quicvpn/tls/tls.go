package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/urfave/cli"
	"io/ioutil"
	"math/big"
	"time"
)

// TlsArgs hold TLS arguments.
var TlsArgs struct {
	CACertPath     string
	CertPath       string
	PrivateKeyPath string
	Insecure       bool
}

// TlsFlags are the CLI input to TlsArgs
var TlsFlags []cli.Flag = []cli.Flag{
	cli.StringFlag{
		Name:        "ca",
		Usage:       "Path to CA cert.",
		Destination: &TlsArgs.CACertPath,
		Value:       "ca.crt",
	},
	cli.StringFlag{
		Name:        "cert",
		Usage:       "Path to certificate.",
		Value:       "cert.crt",
		Destination: &TlsArgs.CertPath,
	},
	cli.StringFlag{
		Name:        "pkey",
		Usage:       "Path to private key.",
		Value:       "key.pem",
		Destination: &TlsArgs.PrivateKeyPath,
	},
	cli.BoolFlag{
		Name:        "insecure, k",
		Usage:       "Ignore TLS errors.",
		Destination: &TlsArgs.Insecure,
	},
}

func LoadCACert() (*x509.CertPool, error) {
	caPool := x509.NewCertPool()
	caData, err := ioutil.ReadFile(TlsArgs.CACertPath)
	if err != nil {
		return nil, err
	}
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("Expected CA cert pem but none found: %s", TlsArgs.CACertPath)
	}
	return caPool, nil
}

func LoadCACertX509() (*x509.Certificate, error) {
	caData, err := ioutil.ReadFile(TlsArgs.CACertPath)
	if err != nil {
		return nil, err
	}

	blk, _ := pem.Decode(caData)
	if blk == nil {
		return nil, errors.New("Ca file did not contain a pem certificate.")
	}

	return x509.ParseCertificate(blk.Bytes)
}

// LoadTLSConfig loads the TLS config using the arguments.
func LoadTLSConfig() (*tls.Config, *x509.Certificate, error) {
	// load the CA cert
	tlsConfig := &tls.Config{InsecureSkipVerify: TlsArgs.Insecure}
	if TlsArgs.CACertPath == "" {
		return nil, nil, errors.New("CA certificate must be given.")
	}

	var err error
	tlsConfig.RootCAs, err = LoadCACert()
	if err != nil {
		return nil, nil, err
	}

	caCert, err := LoadCACertX509()
	if err != nil {
		return nil, nil, err
	}

	serverCert, err := tls.LoadX509KeyPair(TlsArgs.CertPath, TlsArgs.PrivateKeyPath)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig.Certificates = []tls.Certificate{serverCert}
	return tlsConfig, caCert, nil
}

// GenerateTLSCert generates the certificate and private key and saves them to a file.
func GenerateTLSCert() error {
	// Generate the private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := time.Now().Add(time.Duration(24*360) * time.Hour)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(TlsArgs.CertPath, certPEM, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(TlsArgs.PrivateKeyPath, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}

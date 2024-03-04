package identity

import (
	"crypto/rsa"
	"crypto/x509"
	p "encoding/pem"
	"errors"
)

var (
	// ErrNoCertificates is returned when no certificates are found in the PEM.
	ErrNoCertificates = errors.New("no certificates found")
	// ErrNoPrivateKey is returned when no private key is found in the PEM.
	ErrNoPrivateKey = errors.New("no private key found")
	// ErrMultiplePrivateKeys is returned when multiple private keys are found in the PEM.
	ErrMultiplePrivateKeys = errors.New("multiple private keys found")
	// ErrKeyNotRSA is returned when the private key is not an RSA key.
	ErrKeyNotRSA = errors.New("private key is not an RSA key")
)

// CertificatesAndKeyFromPEM extracts the x509 certificates and private key from the given PEM.
func CertificatesAndKeyFromPEM(pem []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	var certs []*x509.Certificate
	var privateKey *rsa.PrivateKey
	for {
		block, rest := p.Decode(pem)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, cert)

		case "RSA PRIVATE KEY":
			if privateKey != nil {
				return nil, nil, ErrMultiplePrivateKeys
			}
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			privateKey = key

		case "PRIVATE KEY":
			if privateKey != nil {
				return nil, nil, ErrMultiplePrivateKeys
			}
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			k, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, ErrKeyNotRSA
			}
			privateKey = k
		}
		pem = rest
	}

	if certs == nil {
		return nil, nil, ErrNoCertificates
	}
	if privateKey == nil {
		return nil, nil, ErrNoPrivateKey
	}

	return certs, privateKey, nil
}

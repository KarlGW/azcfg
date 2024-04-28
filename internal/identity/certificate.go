package identity

import (
	"crypto/rsa"
	"crypto/x509"
	p "encoding/pem"
	"errors"
)

// CertificatesAndKeyFromPEM extracts the x509 certificates and private key from the given PEM.
func CertificatesAndKeyFromPEM(pem []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	if len(pem) == 0 {
		return nil, nil, errors.New("empty pem provided")
	}
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
				return nil, nil, errors.New("multiple private keys found")
			}
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			privateKey = key

		case "PRIVATE KEY":
			if privateKey != nil {
				return nil, nil, errors.New("multiple private keys found")
			}
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			k, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("private key is not an RSA key")
			}
			privateKey = k
		}
		pem = rest
	}

	if certs == nil {
		return nil, nil, errors.New("no certificates found")
	}
	if privateKey == nil {
		return nil, nil, errors.New("no private key found")
	}

	return certs, privateKey, nil
}

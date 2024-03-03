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

// CertificateAndKeyFromPEM extracts the x509 certificates and private key from the given PEM.
// The code for handling the parsing was inspired by the code from ChatGPT, [MSAL library for Go]
// and [Azure SDK for Go]. Which all seem to follow a common and similar pattern.
//
// [MSAL library for Go]: https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/728b089dd0b76102c21c29fcb28adf92cf4d554f/apps/confidential/confidential.go#L70
// [Azure SDK for Go]: https://github.com/Azure/azure-sdk-for-go/blob/6a3e5dc68e51d116eddeb9fd1d2ffbb851be7d57/sdk/azidentity/client_certificate_credential.go#L91

func CertificateAndKeyFromPEM(pem []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
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

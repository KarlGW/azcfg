package testutils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

// Certificate contains a certificate and RSA key pair.
type Certificate struct {
	Cert       *x509.Certificate
	Key        *rsa.PrivateKey
	Thumbprint string
	RawCert    []byte
	RawKey     []byte
}

// CreateCertificateOptions contains options for creating a certificate.
type CreateCertificateOptions struct {
	PKCS1 bool
	PKCS8 bool
}

// CreateCertificateOption is a function that sets options for creating a
// certificate.
type CreateCertificateOption func(o *CreateCertificateOptions)

// CreateCertificate creates a new certificate and RSA key pair.
func CreateCertificate(options ...CreateCertificateOption) (Certificate, error) {
	opts := CreateCertificateOptions{
		PKCS8: true,
	}
	for _, option := range options {
		option(&opts)
	}
	if opts.PKCS1 {
		opts.PKCS8 = false
	}

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"azcfg"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	b, err := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
	if err != nil {
		return Certificate{}, err
	}

	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
		return Certificate{}, err
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return Certificate{}, err
	}

	var kb []byte
	var keyType string
	if opts.PKCS8 {
		kb, err = x509.MarshalPKCS8PrivateKey(pk)
		if err != nil {
			return Certificate{}, err
		}
		keyType = "PRIVATE KEY"
	} else {
		kb = x509.MarshalPKCS1PrivateKey(pk)
		keyType = "RSA PRIVATE KEY"
	}

	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, &pem.Block{Type: keyType, Bytes: kb}); err != nil {
		return Certificate{}, err
	}

	hashed := sha1.Sum(cert.Raw)

	certificate := Certificate{
		Cert:       cert,
		Key:        pk,
		RawCert:    certBuf.Bytes(),
		RawKey:     keyBuf.Bytes(),
		Thumbprint: base64.StdEncoding.EncodeToString(hashed[:]),
	}
	return certificate, nil
}

// WriteCertificateFile writes the certificate(s) to a file.
func WriteCertificateFile(path string, data ...[]byte) (*os.File, error) {
	var content bytes.Buffer
	for _, d := range data {
		_, _ = content.Write(d)
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	if _, err := file.Write(content.Bytes()); err != nil {
		return nil, err
	}
	return file, nil
}

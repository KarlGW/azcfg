package azcfg

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/identity"
)

// CertificateAndKeyFromPEM extracts the x509 certificates and private key from the given PEM.
var CertificateAndKeyFromPEM = identity.CertificateAndKeyFromPEM

// credentialFunc is a function that returns an auth.Credential and an error.
type credentialFunc func() (auth.Credential, error)

// credentialFuncFromOptions gets credential func from the provided options.
// func credentialFromOptions(options Options) (auth.Credential, error) {
func credentialFuncFromOptions(options Options) credentialFunc {
	if len(options.ClientSecret) > 0 {
		return func() (auth.Credential, error) {
			return newClientSecretCredential(options.TenantID, options.ClientID, options.ClientSecret)
		}
	}

	if len(options.Certificates) > 0 && options.PrivateKey != nil {
		return func() (auth.Credential, error) {
			return newClientCertificateCredential(options.TenantID, options.ClientID, options.Certificates, options.PrivateKey)
		}
	}
	if options.UseManagedIdentity {
		return func() (auth.Credential, error) {
			return newManagedIdentityCredential(options.ClientID)
		}
	}
	return nil
}

// credentialFuncsFromEnvironment gets credential func from environment variables.
func credentialFuncFromEnvironment() (credentialFunc, error) {
	tenantID, clientID := os.Getenv(azcfgTenantID), os.Getenv(azcfgClientID)

	if clientSecret := os.Getenv(azcfgClientSecret); len(clientSecret) > 0 {
		return func() (auth.Credential, error) {
			return newClientSecretCredential(tenantID, clientID, clientSecret)
		}, nil
	}

	certificate, certificatePath := os.Getenv(azcfgCertificate), os.Getenv(azcfgCertificatePath)
	if len(certificate) > 0 || len(certificatePath) > 0 {
		certs, key, err := certificateAndKey(certificate, certificatePath)
		if err != nil {
			return nil, err
		}
		return func() (auth.Credential, error) {
			return newClientCertificateCredential(tenantID, clientID, certs, key)
		}, nil
	}

	return func() (auth.Credential, error) {
		return newManagedIdentityCredential(clientID)
	}, nil
}

var newClientSecretCredential = func(tenantID, clientID, clientSecret string) (auth.Credential, error) {
	return identity.NewClientSecretCredential(tenantID, clientID, clientSecret)
}

var newClientCertificateCredential = func(tenantID, clientID string, certificates []*x509.Certificate, key *rsa.PrivateKey) (auth.Credential, error) {
	return identity.NewClientCertificateCredential(tenantID, clientID, certificates, key)
}

var newManagedIdentityCredential = func(clientID string) (auth.Credential, error) {
	return identity.NewManagedIdentityCredential(identity.WithClientID(clientID))
}

// certificateAndKey gets the certificates and keys from the provided certificate or certificate path.
func certificateAndKey(certificate, certificatePath string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	var pem []byte
	var err error
	if len(certificate) > 0 {
		pem, err = base64.StdEncoding.DecodeString(certificate)
	} else if len(certificatePath) > 0 {
		pem, err = os.ReadFile(certificatePath)
	}
	if err != nil {
		return nil, nil, err
	}

	return identity.CertificateAndKeyFromPEM(pem)
}

package identity

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/KarlGW/azcfg/internal/request"
)

// CredentialOptions contains options for the various credential
// types.
type CredentialOptions struct {
	// httpClient is a user provided client to override the default client.
	httpClient request.Client
	// key for a client credential with a certificate (client certificate credential).
	key *rsa.PrivateKey
	// assertion is a function for getting a client assertion for a client credential.
	assertion func() (string, error)
	// clientID is the client ID of the client credential or
	// user assigned identity.
	clientID string
	// secret for a client credential with a secret (client secret credential).
	secret string
	// resourceID of the user assigned identity, use this or clientID
	// to target a specific user assigned identity.
	resourceID string
	// certificates for a client credential with a certificate (client certificate credential).
	certificates []*x509.Certificate
}

// CredentialOption is a function to set *CredentialOptions.
type CredentialOption func(o *CredentialOptions)

// WithClientID sets the client ID.
func WithClientID(id string) CredentialOption {
	return func(o *CredentialOptions) {
		o.clientID = id
	}
}

// WithResourceID sets the resource ID.
func WithResourceID(id string) CredentialOption {
	return func(o *CredentialOptions) {
		o.resourceID = id
	}
}

// WithSecret sets the client secret.
func WithSecret(secret string) CredentialOption {
	return func(o *CredentialOptions) {
		o.secret = secret
	}
}

// WithCertificate sets the certificate and private key.
func WithCertificate(certs []*x509.Certificate, privateKey *rsa.PrivateKey) CredentialOption {
	return func(o *CredentialOptions) {
		o.certificates = certs
		o.key = privateKey
	}
}

// WithHTTPClient sets the HTTP client of the credential.
func WithHTTPClient(c request.Client) CredentialOption {
	return func(o *CredentialOptions) {
		o.httpClient = c
	}
}

// WithAssertion sets the assertion function for the client credential. The provided
// function should return a JWT from an identity provider.
func WithAssertion(assertion func() (string, error)) CredentialOption {
	return func(o *CredentialOptions) {
		o.assertion = assertion
	}
}

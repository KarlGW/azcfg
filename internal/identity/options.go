package identity

import (
	"github.com/KarlGW/azcfg/internal/request"
)

// CredentialOptions contains options for the various credential
// types.
type CredentialOptions struct {
	// httpClient is a user provided client to override the default client.
	httpClient request.Client
	// clientID is the client ID of the client credential or
	// user assigned identity.
	clientID string
	// clientSecret is the secret of a client credential with a shared
	// secret (client secret credential).
	clientSecret string
	// resourceID of the user assigned identity, use this or clientID
	// to target a specific user assigned identity.
	resourceID string
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
		o.clientSecret = secret
	}
}

// WithHTTPClient sets the HTTP client of the credential.
func WithHTTPClient(c request.Client) CredentialOption {
	return func(o *CredentialOptions) {
		o.httpClient = c
	}
}

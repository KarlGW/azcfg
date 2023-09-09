package auth

import (
	"net/http"
)

// httpClient is the interface that wraps around method Do.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CredentialOptions contains options for the various credential
// types.
type CredentialOptions struct {
	// httpClient is a user provided client to override the default client.
	httpClient httpClient
	// clientID is the client ID of the client credential or
	// user assigned identity.
	clientID string
	// clientSecret is the secret of a client credential with a shared
	// secret (client secret credential).
	clientSecret string
	// resourceID of the user assigned identity, use this or clientID
	// to target a specific user assigned identity.
	resourceID string
	// scope is the current scope of the credential.
	scope string
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

// WithScope sets the scope.
func WithScope(scope string) CredentialOption {
	return func(o *CredentialOptions) {
		o.scope = scope
	}
}

// WithHTTPClient sets the HTTP client of the credential.
func WithHTTPClient(c httpClient) CredentialOption {
	return func(o *CredentialOptions) {
		o.httpClient = c
	}
}

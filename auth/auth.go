package auth

import (
	"context"
	"time"
)

// Token contains the access token and when it expires.
type Token struct {
	ExpiresOn   time.Time
	AccessToken string
}

// TokenOptions contains options for a token request.
type TokenOptions struct {
	Scope Scope
}

// TokenOption is a function that sets options for a token request.
type TokenOption func(o *TokenOptions)

// Credential is the interface that wraps around method Token.
type Credential interface {
	Token(ctx context.Context, options ...TokenOption) (Token, error)
}

// Scope represents a scope for a token.
type Scope string

const (
	// ScopeResourceManager is the scope needed for tokens to be used with Azure Resource Manager.
	ScopeResourceManager Scope = "https://management.azure.com/.default"
	// ScopeKeyVault is the scope needed for tokens to be used with Azure Key Vault.
	ScopeKeyVault Scope = "https://vault.azure.net/.default"
	// ScopeAppConfig is the scope needed for tokens to be used with Azure App Config.
	ScopeAppConfig Scope = "https://azconfig.io/.default"
)

// WithScope sets the scope of the token request.
func WithScope(scope Scope) TokenOption {
	return func(o *TokenOptions) {
		o.Scope = scope
	}
}

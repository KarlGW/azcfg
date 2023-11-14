package auth

import (
	"context"
	"time"
)

// Token contains the access token and when it expires.
type Token struct {
	AccessToken string
	ExpiresOn   time.Time
}

// Credential is the interface that wraps around method Token, Scope
// and SetScope.
type Credential interface {
	Token(ctx context.Context) (Token, error)
	Scope() Scope
	SetScope(scope Scope)
}

// Scope represents a scope for a token.
type Scope string

const (
	// ScopeKeyVault is the scope needed for tokens to be used with Azure Key Vault.
	ScopeKeyVault Scope = "https://vault.azure.net/.default"
	// ScopeAppConfig is the scope needed for tokens to be used with Azure App Config.
	ScopeAppConfig Scope = "https://azconfig.io/.default"
)

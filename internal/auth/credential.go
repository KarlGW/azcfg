package auth

import (
	"context"
	"time"
)

var (
	// Scopes contains the target scopes for getting Key Vault secrets.
	Scopes = []string{"https://vault.azure.net/.default"}
)

// Token contains the access token and when it expires.
type Token struct {
	AccessToken string
	ExpiresOn   time.Time
}

// Credential is the interface that wraps around method Token.
type Credential interface {
	Token(ctx context.Context) (Token, error)
}

// AdaptorCredential is used when other credentials are provided than
// the built-in one.
type AdaptorCredential struct {
	TokenFunc func(ctx context.Context) (Token, error)
}

// Token retreives access token.
func (a *AdaptorCredential) Token(ctx context.Context) (Token, error) {
	return a.TokenFunc(ctx)
}

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
	Scope string
}

// TokenOption is a function that sets options for a token request.
type TokenOption func(o *TokenOptions)

// Credential is the interface that wraps around method Token.
type Credential interface {
	Token(ctx context.Context, options ...TokenOption) (Token, error)
}

// WithScope sets the scope of the token request.
func WithScope(scope string) TokenOption {
	return func(o *TokenOptions) {
		o.Scope = scope
	}
}

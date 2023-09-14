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

// Credential is the interface that wraps around method Token.
type Credential interface {
	Token(ctx context.Context) (Token, error)
}

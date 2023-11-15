package authopts

import (
	"context"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/KarlGW/azcfg"
	"github.com/KarlGW/azcfg/auth"
)

// WithTokenCredential is an option that sets the provided azcore.TokenCredential
// to the parser.
func WithTokenCredential(c azcore.TokenCredential) azcfg.Option {
	return func(o *azcfg.Options) {
		o.Credential = &credential{
			TokenCredential: c,
			mu:              &sync.RWMutex{},
			tokens:          make(map[auth.Scope]*auth.Token),
		}
	}
}

// credential is a wrapper around the azcore.TokenCredential.
type credential struct {
	azcore.TokenCredential
	tokens map[auth.Scope]*auth.Token
	mu     *sync.RWMutex
	scope  auth.Scope
}

// Token wraps around the TokenCredential method to satisfy the azcfg.Credential interface.
func (c *credential) Token(ctx context.Context) (auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tokens[c.scope] != nil && c.tokens[c.scope].ExpiresOn.After(time.Now()) {
		return *c.tokens[c.scope], nil
	}

	token, err := c.TokenCredential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{string(c.scope)},
	})
	if err != nil {
		return auth.Token{}, err
	}
	t := auth.Token{
		AccessToken: token.Token,
		ExpiresOn:   token.ExpiresOn,
	}
	c.tokens[c.scope] = &t
	return *c.tokens[c.scope], nil
}

// Scope returns the currnet scope set on the credential.
func (c credential) Scope() auth.Scope {
	return c.scope
}

// SetScope sets the scope on the credential.
func (c *credential) SetScope(scope auth.Scope) {
	c.scope = scope
}

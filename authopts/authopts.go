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
}

// Token wraps around the TokenCredential method to satisfy the azcfg.Credential interface.
func (c *credential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := auth.TokenOptions{
		Scope: auth.ScopeResourceManager,
	}
	for _, option := range options {
		option(&opts)
	}

	if c.tokens[opts.Scope] != nil && c.tokens[opts.Scope].ExpiresOn.UTC().After(time.Now().UTC()) {
		return *c.tokens[opts.Scope], nil
	}

	token, err := c.TokenCredential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{string(opts.Scope)},
	})
	if err != nil {
		return auth.Token{}, err
	}
	t := auth.Token{
		AccessToken: token.Token,
		ExpiresOn:   token.ExpiresOn,
	}
	c.tokens[opts.Scope] = &t
	return *c.tokens[opts.Scope], nil
}

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
		}
	}
}

// credential is a wrapper around the azcore.TokenCredential.
type credential struct {
	azcore.TokenCredential
	token *auth.Token
	mu    *sync.RWMutex
}

// Token wraps around the TokenCredential method to satisfy the azcfg.Credential interface.
func (c *credential) Token(ctx context.Context) (auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != nil && c.token.ExpiresOn.After(time.Now()) {
		return *c.token, nil
	}

	token, err := c.TokenCredential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://vault.azure.net/.default"},
	})
	if err != nil {
		return auth.Token{}, err
	}
	t := auth.Token{
		AccessToken: token.Token,
		ExpiresOn:   token.ExpiresOn,
	}
	c.token = &t
	return *c.token, nil
}

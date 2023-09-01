package azauth

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/KarlGW/azcfg"
	"github.com/KarlGW/azcfg/auth"
)

// WithTokenCredential is an option that sets the provided azcore.TokenCredential
// to the parser.
func WithTokenCredential(c azcore.TokenCredential) azcfg.Option {
	return func(o *azcfg.Options) {
		o.Credential = credential{c}
	}
}

// credential is a wrapper around the azcore.TokenCredential.
type credential struct {
	azcore.TokenCredential
}

// Token wraps around the TokenCredential method to satisfy the azcfg.Credential interface.
func (c credential) Token(ctx context.Context) (auth.Token, error) {
	token, err := c.TokenCredential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: auth.Scopes,
	})
	if err != nil {
		return auth.Token{}, err
	}
	return auth.Token{
		AccessToken: token.Token,
		ExpiresOn:   token.ExpiresOn,
	}, nil
}

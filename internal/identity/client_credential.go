package identity

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/retry"
	"github.com/KarlGW/azcfg/version"
)

const (
	// clientCredentialBaseURL contains the base URL for client credential
	// authentication.
	authEndpoint = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
)

var (
	// ErrMissingCredentials is returned when credentials such as a client secret is missing.
	ErrMissingCredentials = errors.New("missing credentials, needs a shared secret")
)

// ClientCredential represents a client credential for authentication to Azure
// according to the client credential flow. It contains all the necessary settings
// to perform token requests.
type ClientCredential struct {
	c            httpClient
	tokens       map[auth.Scope]*auth.Token
	endpoint     string
	userAgent    string
	tenantID     string
	clientID     string
	clientSecret string
	mu           *sync.RWMutex
}

// NewClientCredential creates and returns a new *ClientCredential.
func NewClientCredential(tenantID string, clientID string, options ...CredentialOption) (*ClientCredential, error) {
	if !validGUID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	if !validGUID(clientID) {
		return nil, ErrInvalidClientID
	}

	c := &ClientCredential{
		c:         &http.Client{},
		tokens:    make(map[auth.Scope]*auth.Token),
		userAgent: "azcfg/" + version.Version(),
		endpoint:  strings.Replace(authEndpoint, "{tenant}", tenantID, 1),
		tenantID:  tenantID,
		clientID:  clientID,
		mu:        &sync.RWMutex{},
	}

	opts := CredentialOptions{}
	for _, option := range options {
		option(&opts)
	}

	if opts.httpClient != nil {
		c.c = opts.httpClient
	}

	if len(opts.clientSecret) > 0 {
		c.clientSecret = opts.clientSecret
	}

	return c, nil
}

// NewClientSecretCredential creates and return a new *ClientCredential with secret
// (ClientSecretCredential).
func NewClientSecretCredential(tenantID, clientID, clientSecret string, options ...CredentialOption) (*ClientCredential, error) {
	if len(clientSecret) == 0 {
		return nil, errors.New("client secret invalid")
	}

	return NewClientCredential(tenantID, clientID, append(options, WithSecret(clientSecret))...)
}

// Token returns a new auth.Token for requests to the Azure REST API.
func (c *ClientCredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := auth.TokenOptions{
		Scope: auth.ScopeResourceManager,
	}
	for _, option := range options {
		option(&opts)
	}

	if c.tokens[opts.Scope] != nil && c.tokens[opts.Scope].ExpiresOn.After(time.Now()) {
		return *c.tokens[opts.Scope], nil
	}

	token, err := c.tokenRequest(ctx, string(opts.Scope))
	if err != nil {
		return auth.Token{}, err
	}
	c.tokens[opts.Scope] = &token
	return *c.tokens[opts.Scope], nil
}

// tokenRequest requests a token after creating the request body
// based on the settings of the ClientCredential.
func (c ClientCredential) tokenRequest(ctx context.Context, scope string) (auth.Token, error) {
	data := url.Values{
		"scope":      {string(scope)},
		"grant_type": {"client_credentials"},
		"client_id":  {c.clientID},
	}
	if len(c.clientSecret) != 0 {
		data.Add("client_secret", c.clientSecret)
	} else {
		return auth.Token{}, ErrMissingCredentials
	}

	var r authResult
	if err := retry.Do(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewBufferString(data.Encode()))
		if err != nil {
			return err
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("User-Agent", c.userAgent)

		r, err = request(c.c, req)
		if err != nil {
			return err
		}
		return nil
	}, func(o *retry.Policy) {
		o.Retry = shouldRetry
	}); err != nil {
		return auth.Token{}, err
	}

	return tokenFromAuthResult(r), nil
}

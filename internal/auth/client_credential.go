package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KarlGW/azcfg"
	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/httpr"
)

const (
	// clientCredentialBaseURL contains the base URL for client credential
	// authentication.
	clientCredentialBaseURL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
)

var (
	// ErrMissingCredentials is returned when credentials such as a client secret is missing.
	ErrMissingCredentials = errors.New("missing credentials, needs a shared secret")
)

// ClientCredential represents a client credential for the Azure REST API
// authentication client credential flow. It contains all the necessary
// settings to perform token requests.
type ClientCredential struct {
	c            httpr.HTTPClient
	token        *auth.Token
	baseURL      string
	tenantID     string
	clientID     string
	clientSecret string
}

// Option is a function that sets options to a *ClientCredential.
type Option func(c *ClientCredential)

// NewClientCredential creates and returns a new ClientCredential.
func NewClientCredential(tenantID string, clientID string, options ...Option) (*ClientCredential, error) {
	if !validGUID(tenantID) {
		return nil, errors.New("tenant ID invalid")
	}
	if !validGUID(clientID) {
		return nil, errors.New("client ID invalid")
	}

	cred := &ClientCredential{
		c:        httpr.NewClient(httpr.WithUserAgent("azcfg/" + azcfg.Version())),
		baseURL:  strings.Replace(clientCredentialBaseURL, "{tenant}", tenantID, 1),
		tenantID: tenantID,
		clientID: clientID,
	}
	for _, option := range options {
		option(cred)
	}

	return cred, nil
}

// Token returns a new auth.Token for requests to the Azure REST API.
func (c *ClientCredential) Token(ctx context.Context) (auth.Token, error) {
	if c.token != nil && c.token.ExpiresOn.After(time.Now()) {
		return *c.token, nil
	}
	token, err := c.tokenRequest(ctx)
	if err != nil {
		return auth.Token{}, err
	}
	c.token = &token
	return *c.token, nil
}

// tokenRequest requests a token after creating the request body
// based on the settings of the ClientCredential.
func (c ClientCredential) tokenRequest(ctx context.Context) (auth.Token, error) {
	data := url.Values{
		"scope":      auth.Scopes,
		"grant_type": {"client_credentials"},
		"client_id":  {c.clientID},
	}
	if len(c.clientSecret) != 0 {
		data.Add("client_secret", c.clientSecret)
	} else {
		return auth.Token{}, ErrMissingCredentials
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return auth.Token{}, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	r, err := request(c.c, req)
	if err != nil {
		return auth.Token{}, err
	}
	return tokenFromAuthResult(r), nil
}

// WithClientSecret sets client secret to the *ClientCredential.
func WithClientSecret(secret string) Option {
	return func(c *ClientCredential) {
		c.clientSecret = secret
	}
}

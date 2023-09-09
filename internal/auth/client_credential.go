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
	authEndpoint = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
)

var (
	// ErrMissingCredentials is returned when credentials such as a client secret is missing.
	ErrMissingCredentials = errors.New("missing credentials, needs a shared secret")
	// ErrInvalidTenantID is returned when an invalid Tenant ID is provided.
	ErrInvalidTenantID = errors.New("invalid tenant ID")
	// ErrInvalidClientID is returned when an invalid Client ID is provided.
	ErrInvalidClientID = errors.New("invalid client ID")
)

// ClientCredential represents a client credential for authentication to Azure
// according to the client credential flow. It contains all the necessary settings
// to perform token requests.
type ClientCredential struct {
	c            httpClient
	token        *auth.Token
	endpoint     string
	tenantID     string
	clientID     string
	clientSecret string
	scope        string
}

// NewClientCredential creates and returns a new *ClientCredential.
func NewClientCredential(tenantID string, clientID string, options ...CredentialOption) (*ClientCredential, error) {
	if !validGUID(tenantID) {
		return nil, ErrInvalidTenantID
	}
	if !validGUID(clientID) {
		return nil, ErrInvalidClientID
	}

	cred := &ClientCredential{
		c:        httpr.NewClient(httpr.WithUserAgent("azcfg/" + azcfg.Version())),
		endpoint: strings.Replace(authEndpoint, "{tenant}", tenantID, 1),
		tenantID: tenantID,
		clientID: clientID,
	}

	opts := CredentialOptions{}
	for _, option := range options {
		option(&opts)
	}
	if opts.httpClient != nil {
		cred.c = opts.httpClient
	}
	if len(opts.clientSecret) > 0 {
		cred.clientSecret = opts.clientSecret
	}
	if len(opts.scope) > 0 {
		cred.scope = opts.scope
	}

	return cred, nil
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
		"scope":      {c.scope},
		"grant_type": {"client_credentials"},
		"client_id":  {c.clientID},
	}
	if len(c.clientSecret) != 0 {
		data.Add("client_secret", c.clientSecret)
	} else {
		return auth.Token{}, ErrMissingCredentials
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewBufferString(data.Encode()))
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

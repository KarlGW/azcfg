package identity

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/version"
)

// ClientCredential represents a client credential for authentication to Azure
// according to the client credential flow. It contains all the necessary settings
// to perform token requests.
type ClientCredential struct {
	c           request.Client
	tokens      map[string]*auth.Token
	assertion   func() (string, error)
	cloud       cloud.Cloud
	endpoint    string
	userAgent   string
	tenantID    string
	clientID    string
	secret      string
	certificate certificate
	mu          sync.RWMutex
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
		c:         httpr.NewClient(),
		tokens:    make(map[string]*auth.Token),
		cloud:     cloud.AzurePublic,
		userAgent: "azcfg/" + version.Version(),
		tenantID:  tenantID,
		clientID:  clientID,
	}

	opts := CredentialOptions{}
	for _, option := range options {
		option(&opts)
	}
	c.endpoint = endpoint(c.cloud, tenantID)

	if opts.httpClient != nil {
		c.c = opts.httpClient
	}

	if len(opts.secret) > 0 {
		c.secret = opts.secret
	}
	if len(opts.certificates) > 0 {
		cert, err := newCertificate(opts.certificates, opts.key)
		if err != nil {
			return nil, err
		}
		c.certificate = cert
	}
	if opts.assertion != nil {
		c.assertion = opts.assertion
	}

	return c, nil
}

// NewClientSecretCredential creates and return a new *ClientCredential with a
// secret (client secret credential).
func NewClientSecretCredential(tenantID, clientID, secret string, options ...CredentialOption) (*ClientCredential, error) {
	if len(secret) == 0 {
		return nil, errors.New("client secret invalid")
	}

	return NewClientCredential(tenantID, clientID, append(options, WithSecret(secret))...)
}

// NewClientCertificateCredential creates and returns a new *ClientCredential with
// a certificate and private key (client certificate credential).
func NewClientCertificateCredential(tenantID, clientID string, certificates []*x509.Certificate, key *rsa.PrivateKey, options ...CredentialOption) (*ClientCredential, error) {
	if len(certificates) == 0 {
		return nil, errors.New("client certificate invalid")
	}
	if key == nil {
		return nil, errors.New("client certificate key invalid")
	}

	return NewClientCredential(tenantID, clientID, append(options, WithCertificate(certificates, key))...)
}

// NewClientAssertionCredential creates and returns a new *ClientCredential with
// a client assertion function (client assertion credential).
func NewClientAssertionCredential(tenantID, clientID string, assertion func() (string, error), options ...CredentialOption) (*ClientCredential, error) {
	if assertion == nil {
		return nil, errors.New("client assertion function invalid")
	}
	return NewClientCredential(tenantID, clientID, append(options, WithAssertion(assertion))...)
}

// Token returns a new auth.Token for requests to the Azure REST API.
func (c *ClientCredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := auth.TokenOptions{}
	for _, option := range options {
		option(&opts)
	}

	if c.tokens[opts.Scope] != nil && c.tokens[opts.Scope].ExpiresOn.UTC().After(time.Now().UTC()) {
		return *c.tokens[opts.Scope], nil
	}

	token, err := c.tokenRequest(ctx, opts.Scope)
	if err != nil {
		return auth.Token{}, err
	}
	c.tokens[opts.Scope] = &token
	return *c.tokens[opts.Scope], nil
}

// tokenRequest requests a token after creating the request body
// based on the settings of the ClientCredential.
func (c *ClientCredential) tokenRequest(ctx context.Context, scope string) (auth.Token, error) {
	data := url.Values{
		"scope":      {scope},
		"grant_type": {"client_credentials"},
		"client_id":  {c.clientID},
	}
	if len(c.secret) != 0 {
		data.Add("client_secret", c.secret)
	} else if !c.certificate.isZero() {
		assertion, err := newCertificateAssertion(c.endpoint, c.clientID, c.certificate)
		if err != nil {
			return auth.Token{}, err
		}
		data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Add("client_assertion", assertion.Encode())
	} else if c.assertion != nil {
		assertion, err := c.assertion()
		if err != nil {
			return auth.Token{}, err
		}
		data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Add("client_assertion", assertion)
	} else {
		return auth.Token{}, ErrInvalidCredential
	}

	headers := http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
		"User-Agent":   []string{c.userAgent},
	}

	resp, err := request.Do(ctx, c.c, headers, http.MethodPost, c.endpoint, []byte(data.Encode()))
	if err != nil {
		return auth.Token{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusNoContent {
		var authErr authError
		if err := json.Unmarshal(resp.Body, &authErr); err != nil {
			return auth.Token{}, err
		}
		authErr.StatusCode = resp.StatusCode
		return auth.Token{}, authErr
	}

	var r authResult
	if err := json.Unmarshal(resp.Body, &r); err != nil {
		return auth.Token{}, err
	}

	return tokenFromAuthResult(r), nil
}

// endpoint returns the base endpoint for the provided cloud.
func endpoint(c cloud.Cloud, tenantID string) string {
	var uri string
	switch c {
	case cloud.AzurePublic:
		uri = "login.microsoftonline.com"
	case cloud.AzureGovernment:
		uri = "login.microsoftonline.us"
	case cloud.AzureChina:
		uri = "login.chinacloudapi.cn"
	}
	return fmt.Sprintf("https://%s/%s/oauth2/v2.0/token", uri, tenantID)

}

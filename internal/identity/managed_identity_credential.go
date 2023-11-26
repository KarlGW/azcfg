package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/version"
)

var (
	// ErrUnsupportedManagedIdentityType is returned when the type of the managed identity
	// cannot be established.
	ErrUnsupportedManagedIdentityType = errors.New("unsupported managed identity type")
	// ErrInvalidManagedIdentityResourceID is returned when an invalid managed
	// identity resource ID is provided.
	ErrInvalidManagedIdentityResourceID = errors.New("invalid managed identity resource ID")
)

const (
	// imdsEndpoint contains the endpoint for managed identity requests based on
	// IMDS (Azure Instance Metadata Service).
	imdsEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
	// imdsAPIVersion contains API version for managed identity requests baed on
	// IMDS (Azure Instance Metadata Service).
	imdsAPIVersion = "2018-02-01"
)

const (
	// appServiceAPIVersion contains API version for managed identity requests
	// based on app services.
	appServiceAPIVersion = "2019-08-01"
)

const (
	// identityEndpoint is the environment variable name set on non-IMDS setups
	// for the environment variable containing the identity endpoint.
	identityEndpoint = "IDENTITY_ENDPOINT"
	// identityHeader is the environment variable name set on non-IMDS setups
	// for the environment variable containing the identity header.
	identityHeader = "IDENTITY_HEADER"
)

// ManagedIdentityCredential represents a managed identity credential for authentication
// to Azure according to the managed identity credential flow. It contains all the necessary
// settings to perform token requests.
type ManagedIdentityCredential struct {
	c          request.Client
	header     http.Header
	tokens     map[auth.Scope]*auth.Token
	endpoint   string
	userAgent  string
	apiVersion string
	clientID   string
	resourceID string
	mu         sync.RWMutex
}

// NewManagedIdentityCredential creates and returns a new *ManagedIdentityCredential.
func NewManagedIdentityCredential(options ...CredentialOption) (*ManagedIdentityCredential, error) {
	c := &ManagedIdentityCredential{
		c:         httpr.NewClient(),
		header:    http.Header{},
		tokens:    make(map[auth.Scope]*auth.Token),
		userAgent: "azcfg/" + version.Version(),
	}
	opts := CredentialOptions{}
	for _, option := range options {
		option(&opts)
	}

	if opts.httpClient != nil {
		c.c = opts.httpClient
	}

	if len(opts.clientID) > 0 {
		if !validGUID(opts.clientID) {
			return nil, ErrInvalidClientID
		}
		c.clientID = opts.clientID
	}

	if len(opts.resourceID) > 0 {
		if !validManagedIdentityResourceID(opts.resourceID) {
			return nil, ErrInvalidManagedIdentityResourceID
		}
		c.resourceID = opts.resourceID
	}

	if endpoint, ok := os.LookupEnv(identityEndpoint); ok {
		if header, ok := os.LookupEnv(identityHeader); ok {
			c.endpoint, c.apiVersion = endpoint, appServiceAPIVersion
			c.header.Add("X-Identity-Header", header)
		} else {
			return nil, ErrUnsupportedManagedIdentityType
		}
	} else {
		c.endpoint, c.apiVersion = imdsEndpoint, imdsAPIVersion
		c.header.Add("Metadata", "true")
	}

	return c, nil
}

// Token returns a new auth.Token for requests to the Azure REST API.
func (c *ManagedIdentityCredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
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

	token, err := c.tokenRequest(ctx, string(opts.Scope))
	if err != nil {
		return auth.Token{}, err
	}
	c.tokens[opts.Scope] = &token
	return *c.tokens[opts.Scope], nil
}

// tokenRequest requests a token after creating the request body
// based on the settings of the ManagedIdentityCredential.
func (c *ManagedIdentityCredential) tokenRequest(ctx context.Context, scope string) (auth.Token, error) {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return auth.Token{}, err
	}
	qs := url.Values{
		"resource":    {strings.TrimSuffix(string(scope), "/.default")},
		"api-version": {c.apiVersion},
	}
	if len(c.clientID) > 0 {
		qs.Add("client_id", c.clientID)
	} else if len(c.resourceID) > 0 {
		qs.Add("mi_res_id", c.resourceID)
	}
	u.RawQuery = qs.Encode()

	headers := http.Header{
		"User-Agent": []string{c.userAgent},
	}
	for k, v := range c.header {
		headers.Add(k, v[0])
	}

	resp, err := request.Do(ctx, c.c, headers, http.MethodGet, u.String(), nil)
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

package identity

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/retry"
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
	c          httpClient
	header     http.Header
	token      *auth.Token
	endpoint   string
	apiVersion string
	clientID   string
	resourceID string
	scope      string
	mu         *sync.RWMutex
}

// NewManagedIdentityCredential creates and returns a new *ManagedIdentityCredential.
func NewManagedIdentityCredential(options ...CredentialOption) (*ManagedIdentityCredential, error) {
	c := &ManagedIdentityCredential{
		c: &http.Client{},
		header: http.Header{
			"User-Agent": {"azcfg/" + version.Version()},
		},
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

	if len(opts.scope) > 0 {
		c.scope = strings.TrimSuffix(opts.scope, "/.default")
	} else {
		c.scope = defaultResource
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
func (c *ManagedIdentityCredential) Token(ctx context.Context) (auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
// based on the settings of the ManagedIdentityCredential.
func (c ManagedIdentityCredential) tokenRequest(ctx context.Context) (auth.Token, error) {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return auth.Token{}, err
	}
	qs := url.Values{
		"resource":    {c.scope},
		"api-version": {c.apiVersion},
	}
	if len(c.clientID) > 0 {
		qs.Add("client_id", c.clientID)
	} else if len(c.resourceID) > 0 {
		qs.Add("mi_res_id", c.resourceID)
	}
	u.RawQuery = qs.Encode()

	var r authResult
	if err := retry.Do(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		for k, v := range c.header {
			req.Header.Add(k, strings.Join(v, ", "))
		}

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

package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/retry"
	"golang.org/x/sync/errgroup"
)

const (
	// baseURL is the base URL for Azure Key Vault in the Azure Public Cloud.
	baseURL = "https://{vault}.vault.azure.net/secrets"
)

const (
	// apiVersion is the API version of the Key Vault REST API endpoint.
	apiVersion = "7.4"
)

// Secret represents a secret as returned from the Key Vault REST API.
type Secret struct {
	Value string `json:"value"`
}

// httpClient is an interface that wraps around method Do.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client contains methods to call the Azure Key Vault REST API and
// base settings for handling the requests.
type Client struct {
	c           httpClient
	cred        auth.Credential
	concurrency int
	timeout     time.Duration
	baseURL     string
}

// ClientOptions contains options for the Client.
type ClientOptions struct {
	HTTPClient  httpClient
	Concurrency int
	Timeout     time.Duration
}

// ClientOption is a function that sets options to *ClientOptions.
type ClientOption func(o *ClientOptions)

// NewClient creates and returns a new Client.
func NewClient(vault string, cred auth.Credential, options ...ClientOption) *Client {
	opts := ClientOptions{
		Concurrency: 10,
		Timeout:     time.Millisecond * 1000 * 10,
	}
	for _, option := range options {
		option(&opts)
	}

	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{
			Timeout: opts.Timeout,
		}
	}

	return &Client{
		c:           opts.HTTPClient,
		cred:        cred,
		timeout:     opts.Timeout,
		concurrency: opts.Concurrency,
		baseURL:     strings.Replace(baseURL, "{vault}", vault, 1),
	}
}

// Get secrets by names.
func (c Client) Get(names ...string) (map[string]Secret, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	return c.getSecrets(ctx, names)
}

// get a secret.
func (c Client) get(ctx context.Context, name string) (Secret, error) {
	u := fmt.Sprintf("%s/%s?api-version=%s", c.baseURL, name, apiVersion)
	token, err := c.cred.Token(ctx)
	if err != nil {
		return Secret{}, err
	}

	var b []byte
	if err := retry.Do(ctx, func() error {
		b, err = request(ctx, c.c, addAuthHeader(http.Header{}, token.AccessToken), http.MethodGet, u)
		if err != nil {
			if errors.Is(err, errSecretNotFound) {
				err = fmt.Errorf("secret %s: %w", name, err)
			}
			return err
		}
		return nil
	}, func(o *retry.Policy) {
		o.Retry = shouldRetry
	}); err != nil {
		return Secret{}, err
	}

	var secret Secret
	if err := json.Unmarshal(b, &secret); err != nil {
		return secret, err
	}

	return secret, nil
}

// getSecrets gets secrets by the provided names and returns them as a map[string]Secret
// where the secret name is the key.
func (c Client) getSecrets(ctx context.Context, names []string) (map[string]Secret, error) {
	if names == nil {
		return nil, nil
	}
	sm := secretMap{
		m: make(map[string]Secret, len(names)),
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(c.concurrency)
	for _, name := range names {
		name := name
		g.Go(func() error {
			secret, err := c.get(ctx, name)
			if err != nil && !errors.Is(err, errSecretNotFound) {
				return err
			}
			sm.set(name, secret)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return sm.m, nil
}

// secretMap provides a concurrency safe way to manipulate
// the inner map.
type secretMap struct {
	m  map[string]Secret
	mu sync.RWMutex
}

// set a secret to the secretMap.
func (sm *secretMap) set(key string, secret Secret) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.m[key] = secret
}

// WithConcurrency sets the concurrency for secret retrieval.
func WithConcurrency(c int) ClientOption {
	return func(o *ClientOptions) {
		o.Concurrency = c
	}
}

// WithTimeout sets timeout for secret retreival.
func WithTimeout(d time.Duration) ClientOption {
	return func(o *ClientOptions) {
		o.Timeout = d
	}
}

// shouldRetry contains retry policy for secret requests.
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	var e errorResponse
	if errors.As(err, &e) {
		if e.StatusCode == 0 || e.StatusCode == http.StatusInternalServerError {
			return true
		}
	}
	return false
}

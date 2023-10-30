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
	"github.com/KarlGW/azcfg/version"
)

const (
	// baseURL is the base URL for Azure Key Vault in the Azure Public Cloud.
	baseURL = "https://{vault}.vault.azure.net/secrets"
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
	header      http.Header
	baseURL     string
	concurrency int
	timeout     time.Duration
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
		Timeout:     time.Second * 10,
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
		c:    opts.HTTPClient,
		cred: cred,
		header: http.Header{
			"User-Agent": {"azcfg/" + version.Version()},
		},
		baseURL:     strings.Replace(baseURL, "{vault}", vault, 1),
		concurrency: opts.Concurrency,
		timeout:     opts.Timeout,
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
		b, err = request(ctx, c.c, addAuthHeader(c.header, token.AccessToken), http.MethodGet, u)
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

// secretResults contains results from retreiving secrets. Should
// be used with a channel for handling results and errors.
type secretResult struct {
	name   string
	secret Secret
	err    error
}

// getSecrets gets secrets by the provided names and returns them as a map[string]Secret
// where the secret name is the key.
func (c Client) getSecrets(ctx context.Context, names []string) (map[string]Secret, error) {
	namesCh := make(chan string)
	srCh := make(chan secretResult)

	go func() {
		for _, name := range names {
			namesCh <- name
		}
		close(namesCh)
	}()

	concurrency := c.concurrency
	if len(names) < concurrency {
		concurrency = len(names)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 1; i <= concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case name, ok := <-namesCh:
					if !ok {
						return
					}
					sr := secretResult{name: name}
					secret, err := c.get(ctx, name)
					if err != nil && !errors.Is(err, errSecretNotFound) {
						sr.err = err
						srCh <- sr
						cancel()
						return
					}
					sr.secret = secret
					srCh <- sr
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(srCh)
	}()

	secrets := make(map[string]Secret)
	for sr := range srCh {
		if sr.err != nil {
			return nil, sr.err
		}
		secrets[sr.name] = sr.secret
	}

	return secrets, nil
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

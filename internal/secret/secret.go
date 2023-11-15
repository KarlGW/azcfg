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
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/internal/retry"
	"github.com/KarlGW/azcfg/version"
)

const (
	// baseURL is the base URL for Azure Key Vault in the Azure Public Cloud.
	baseURL = "https://{vault}.vault.azure.net/secrets"
	// apiVersion is the API version of the Key Vault REST API endpoint.
	apiVersion = "7.4"
	// defaultConcurrency is the default concurrency set on the client.
	defaultConcurrency = 10
	// defaultTimeout is the default timeout set on the client.
	defaultTimeout = time.Second * 10
)

// Secret represents a secret as returned from the Key Vault REST API.
type Secret struct {
	Value string `json:"value"`
}

// Client contains methods to call the Azure Key Vault REST API and
// base settings for handling the requests.
type Client struct {
	c           request.Client
	cred        auth.Credential
	baseURL     string
	userAgent   string
	concurrency int
	timeout     time.Duration
}

// ClientOption is a function that sets options to *Client.
type ClientOption func(o *Client)

// NewClient creates and returns a new Client.
func NewClient(vault string, cred auth.Credential, options ...ClientOption) *Client {
	c := &Client{
		cred:        cred,
		baseURL:     strings.Replace(baseURL, "{vault}", vault, 1),
		userAgent:   "azcfg/" + version.Version(),
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
	for _, option := range options {
		option(c)
	}
	if c.c == nil {
		c.c = &http.Client{
			Timeout: c.timeout,
		}
	}
	return c
}

// Options for client operations.
type Options struct{}

// Option is a function that sets options for client operations.
type Option func(o *Options)

// Get secrets by names.
func (c Client) GetSecrets(names []string, options ...Option) (map[string]Secret, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	return c.getSecrets(ctx, names, options...)
}

// get a secret.
func (c Client) Get(ctx context.Context, name string, options ...Option) (Secret, error) {
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}

	u := fmt.Sprintf("%s/%s?api-version=%s", c.baseURL, name, apiVersion)
	if c.cred.Scope() != auth.ScopeKeyVault {
		c.cred.SetScope(auth.ScopeKeyVault)
	}
	token, err := c.cred.Token(ctx)
	if err != nil {
		return Secret{}, err
	}

	header := http.Header{
		"User-Agent":    []string{c.userAgent},
		"Authorization": []string{"Bearer " + token.AccessToken},
	}

	var b []byte
	if err := retry.Do(ctx, func() error {
		b, err = request.Do(ctx, c.c, header, http.MethodGet, u)
		if err != nil {
			if errors.Is(err, request.ErrNotFound) {
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
func (c Client) getSecrets(ctx context.Context, names []string, options ...Option) (map[string]Secret, error) {
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
					secret, err := c.Get(ctx, name)
					if err != nil && !errors.Is(err, request.ErrNotFound) {
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
	return func(cl *Client) {
		cl.concurrency = c
	}
}

// WithTimeout sets timeout for secret retreival.
func WithTimeout(d time.Duration) ClientOption {
	return func(cl *Client) {
		cl.timeout = d
	}
}

// shouldRetry contains retry policy for secret requests.
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	var e request.ErrorResponse
	if errors.As(err, &e) {
		if e.StatusCode == 0 || e.StatusCode == http.StatusInternalServerError {
			return true
		}
	}
	return false
}

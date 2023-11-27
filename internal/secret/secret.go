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
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/request"
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

// GetValue returns the Value of the Secret.
func (s Secret) GetValue() string {
	return s.Value
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
type ClientOption func(c *Client)

// NewClient creates and returns a new Client.
func NewClient(keyVault string, cred auth.Credential, options ...ClientOption) *Client {
	c := &Client{
		cred:        cred,
		baseURL:     strings.Replace(baseURL, "{vault}", keyVault, 1),
		userAgent:   "azcfg/" + version.Version(),
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
	for _, option := range options {
		option(c)
	}
	if c.c == nil {
		c.c = httpr.NewClient()
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
	token, err := c.cred.Token(ctx, auth.WithScope(auth.ScopeKeyVault))
	if err != nil {
		return Secret{}, err
	}

	headers := http.Header{
		"User-Agent":    []string{c.userAgent},
		"Authorization": []string{"Bearer " + token.AccessToken},
	}

	resp, err := request.Do(ctx, c.c, headers, http.MethodGet, u, nil)
	if err != nil {
		return Secret{}, err
	}

	if resp.StatusCode != http.StatusOK {
		var secretErr secretError
		if err := json.Unmarshal(resp.Body, &secretErr); err != nil {
			return Secret{}, err
		}
		secretErr.StatusCode = resp.StatusCode
		return Secret{}, secretErr
	}

	var secret Secret
	if err := json.Unmarshal(resp.Body, &secret); err != nil {
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
					secret, err := c.Get(ctx, name, options...)
					if err != nil && !isSecretError(err, http.StatusNotFound) {
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

// secretError represents an error returned from the Key Vault REST API.
type secretError struct {
	Err struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	StatusCode int
}

// Error returns the message from the secretError.
func (e secretError) Error() string {
	return e.Err.Message
}

// isSecretError checks if the provided error is a secretError.
// If the optional statusCodes is provided it further
// requires that they should match that with the
// provided error.
func isSecretError(err error, statusCodes ...int) bool {
	var secretErr secretError
	if errors.As(err, &secretErr) {
		if len(statusCodes) == 0 {
			return true
		} else {
			for _, statusCode := range statusCodes {
				if secretErr.StatusCode == statusCode {
					return true
				}
			}
		}

	}
	return false
}

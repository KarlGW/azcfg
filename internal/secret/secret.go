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
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/version"
)

const (
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
	cloud       cloud.Cloud
	scope       string
	baseURL     string
	vault       string
	userAgent   string
	retryPolicy httpr.RetryPolicy
	concurrency int
	timeout     time.Duration
}

// ClientOption is a function that sets options to *Client.
type ClientOption func(c *Client)

// NewClient creates and returns a new *Client.
func NewClient(vault string, cred auth.Credential, options ...ClientOption) (*Client, error) {
	if len(vault) == 0 {
		return nil, errors.New("empty key vault name")
	}
	if cred == nil {
		return nil, errors.New("nil credential")
	}
	c := &Client{
		cred:        cred,
		cloud:       cloud.AzurePublic,
		vault:       vault,
		userAgent:   "azcfg/" + version.Version(),
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
	for _, option := range options {
		option(c)
	}

	if len(c.baseURL) == 0 {
		c.baseURL = endpoint(c.cloud, vault)
	}

	if len(c.scope) == 0 {
		c.scope = scope(c.cloud)
	}

	if c.c == nil {
		c.c = httpr.NewClient(
			httpr.WithTimeout(c.timeout),
			httpr.WithRetryPolicy(c.retryPolicy),
		)
	}
	return c, nil
}

// Options for client operations.
type Options struct{}

// Option is a function that sets options for client operations.
type Option func(o *Options)

// GetSecrets gets secrets by names.
func (c Client) GetSecrets(ctx context.Context, names []string, options ...Option) (map[string]Secret, error) {
	return c.getSecrets(ctx, names, options...)
}

// Get a secret.
func (c Client) Get(ctx context.Context, name string, options ...Option) (Secret, error) {
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}

	u := fmt.Sprintf("%s/%s?api-version=%s", c.baseURL, name, apiVersion)
	token, err := c.cred.Token(ctx, auth.WithScope(c.scope))
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
		if len(resp.Body) > 0 {
			if err := json.Unmarshal(resp.Body, &secretErr); err != nil {
				return Secret{}, err
			}
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

// Vault returns the vault for the client.
func (c Client) Vault() string {
	return c.vault
}

// SetVault sets the vault for the client.
func (c *Client) SetVault(vault string) {
	c.baseURL = strings.Replace(c.baseURL, c.vault, vault, 1)
	c.vault = vault
}

// secretResults contains results from retreiving secrets. Should
// be used with a channel for handling results and errors.
type secretResult struct {
	secret Secret
	err    error
	name   string
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
					if err != nil && !isSecretNotFound(err) {
						sr.err = err
						srCh <- sr
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

// uri returns the base URI for the provided cloud.
func uri(c cloud.Cloud) string {
	switch c {
	case cloud.AzurePublic:
		return "vault.azure.net"
	case cloud.AzureGovernment:
		return "vault.usgovcloudapi.net"
	case cloud.AzureChina:
		return "vault.azure.cn"
	}
	return ""
}

// endpoint returns the base endpoint for the provided cloud.
func endpoint(cloud cloud.Cloud, vault string) string {
	return fmt.Sprintf("https://%s.%s/secrets", vault, uri(cloud))
}

// scope returns the scope for the provided cloud.
func scope(cloud cloud.Cloud) string {
	return fmt.Sprintf("https://%s/.default", uri(cloud))
}

package setting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/version"
)

const (
	// apiVersion is the API version for the App Config REST API endpoint.
	apiVersion = "1.0"
	// defaultConcurrency is the default concurrency set on the client.
	defaultConcurrency = 10
	// defaultTimeout is the default timeout set on the client.
	defaultTimeout = time.Second * 10
)

const (
	// keyVaultReferenceContentType is the content type for a key vault reference.
	keyVaultReferenceContentType = "application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8"
)

// Setting represents a setting as returned from the App Config REST API.
type Setting struct {
	ContentType string `json:"content_type"`
	Value       string `json:"value"`
	Label       string `json:"label"`
}

// GetValue returns the Value of the Setting.
func (s Setting) GetValue() string {
	return s.Value
}

// secretClient is the interface that wraps around method Get, Vault and
// SetVault.
type secretClient interface {
	Get(ctx context.Context, name string, options ...secret.Option) (secret.Secret, error)
	Vault() string
	SetVault(vault string)
}

// Client contains methods to call the Azure App Config REST API and
// base settings for handling the requests.
type Client struct {
	c           request.Client
	cred        auth.Credential
	sc          secretClient
	cloud       cloud.Cloud
	scope       string
	baseURL     string
	userAgent   string
	retryPolicy httpr.RetryPolicy
	concurrency int
	timeout     time.Duration
	mu          sync.RWMutex
}

// ClientOption is a function that sets options to *Client.
type ClientOption func(c *Client)

// NewClient creates and returns a new Client.
func NewClient(appConfiguration string, cred auth.Credential, options ...ClientOption) *Client {
	c := &Client{
		cred:        cred,
		cloud:       cloud.AzurePublic,
		userAgent:   "azcfg/" + version.Version(),
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
	for _, option := range options {
		option(c)
	}

	if len(c.baseURL) == 0 {
		c.baseURL = endpoint(c.cloud, appConfiguration)
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
	return c
}

// Options for client operations.
type Options struct {
	Label string
}

// Option is a function that sets options for client operations.
type Option func(o *Options)

// GetSettings get settings (key-values) by keys.
func (c *Client) GetSettings(ctx context.Context, keys []string, options ...Option) (map[string]Setting, error) {
	return c.getSettings(ctx, keys, options...)
}

// Get a setting.
func (c *Client) Get(ctx context.Context, key string, options ...Option) (Setting, error) {
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}

	u := fmt.Sprintf("%s/kv/%s?api-version=%s", c.baseURL, key, apiVersion)
	if len(opts.Label) > 0 {
		u += "&label=" + opts.Label
	}

	var authHeader string
	if c.cred != nil {
		token, err := c.cred.Token(ctx, auth.WithScope(c.scope))
		if err != nil {
			return Setting{}, err
		}
		authHeader = "Bearer " + token.AccessToken
	} else {
		// Create auth header value credential and secret.
		// Add this functionality further on.
		authHeader = ""
	}

	headers := http.Header{
		"User-Agent":    []string{c.userAgent},
		"Authorization": []string{authHeader},
	}

	resp, err := request.Do(ctx, c.c, headers, http.MethodGet, u, nil)
	if err != nil {
		return Setting{}, err
	}

	if resp.StatusCode != http.StatusOK {
		var settingErr settingError
		if len(resp.Body) > 0 {
			if err := json.Unmarshal(resp.Body, &settingErr); err != nil {
				return Setting{}, err
			}
		}

		if len(settingErr.Detail) == 0 {
			settingErr = newSettingError(key, resp.StatusCode)
		} else {
			settingErr.StatusCode = resp.StatusCode
		}

		return Setting{}, settingErr
	}

	var setting Setting
	if err := json.Unmarshal(resp.Body, &setting); err != nil {
		return setting, err
	}

	if setting.ContentType != keyVaultReferenceContentType {
		return setting, nil
	}

	var reference struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal([]byte(setting.Value), &reference); err != nil {
		return setting, err
	}

	secret, err := c.getSecret(ctx, reference.URI)
	if err != nil {
		return Setting{}, err
	}

	setting.Value = secret.Value

	return setting, nil
}

// getSecret gets a secret from the provided URI.
func (c *Client) getSecret(ctx context.Context, uri string) (secret.Secret, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v, s, err := vaultAndSecret(uri)
	if err != nil {
		return secret.Secret{}, err
	}
	if c.sc == nil {
		c.sc = newSecretClient(v, c.cred,
			secret.WithConcurrency(c.concurrency),
			secret.WithTimeout(c.timeout),
			secret.WithRetryPolicy(c.retryPolicy),
		)
	} else {
		if c.sc.Vault() != v {
			c.sc.SetVault(v)
		}
	}
	sec, err := c.sc.Get(ctx, s)
	if err != nil {
		return secret.Secret{}, err
	}
	return sec, nil
}

// settingResult contains result from retreiving settings. Should
// be used with a channel for handling results and errors.
type settingResult struct {
	setting Setting
	err     error
	key     string
}

// getSettings gets settings by the provided keys and returns them as a map[string]Setting
// where setting key is the key.
func (c *Client) getSettings(ctx context.Context, keys []string, options ...Option) (map[string]Setting, error) {
	keysCh := make(chan string)
	srCh := make(chan settingResult)

	go func() {
		for _, key := range keys {
			keysCh <- key
		}
		close(keysCh)
	}()

	concurrency := c.concurrency
	if len(keys) < concurrency {
		concurrency = len(keys)
	}

	var wg sync.WaitGroup
	for i := 1; i <= concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case key, ok := <-keysCh:
					if !ok {
						return
					}
					sr := settingResult{key: key}
					setting, err := c.Get(ctx, key, options...)
					if err != nil && !isSettingNotFound(err) {
						sr.err = err
						srCh <- sr
						return
					}
					sr.setting = setting
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

	settings := make(map[string]Setting)
	for sr := range srCh {
		if sr.err != nil {
			return nil, sr.err
		}
		settings[sr.key] = sr.setting
	}
	return settings, nil
}

// vaultAndSecret returns the vault and secret from the provided URL.
func vaultAndSecret(rawURL string) (string, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || len(u.Scheme) == 0 {
		return "", "", ErrParseSecretURL
	}

	vault := strings.Split(u.Hostname(), ".")[0]
	secret := strings.TrimPrefix(u.Path, "/secrets/")

	return vault, secret, nil
}

var newSecretClient = func(vault string, cred auth.Credential, options ...secret.ClientOption) secretClient {
	return secret.NewClient(vault, cred, options...)
}

// uri returns the base URI for the provided cloud.
func uri(c cloud.Cloud) string {
	switch c {
	case cloud.AzurePublic:
		return "azconfig.io"
	case cloud.AzureGovernment:
		return "azconfig.azure.us"
	case cloud.AzureChina:
		return "azconfig.azure.cn"
	}
	return ""
}

// endpoint returns the base endpoint for the provided cloud.
func endpoint(cloud cloud.Cloud, appConfiguration string) string {
	return fmt.Sprintf("https://%s.%s", appConfiguration, uri(cloud))
}

// scope returns the scope for the provided cloud.
func scope(cloud cloud.Cloud) string {
	return fmt.Sprintf("https://%s/.default", uri(cloud))
}

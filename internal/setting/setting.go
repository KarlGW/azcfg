package setting

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
	// baseURL is the base URL for Azure App Config in the Azure Public Cloud.
	baseURL = "https://{config}.azconfig.io"
	// apiVersion is the API version for the App Config REST API endpoint.
	apiVersion = "1.0"
	// defaultConcurrency is the default concurrency set on the client.
	defaultConcurrency = 10
	// defaultTimeout is the default timeout set on the client.
	defaultTimeout = time.Second * 10
)

// Setting represents a setting as returned from the App Config REST API.
type Setting struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// GetValue returns the Value of the Setting.
func (s Setting) GetValue() string {
	return s.Value
}

// Client contains methods to call the Azure App Config REST API and
// base settings for handling the requests.
type Client struct {
	c                request.Client
	cred             auth.Credential
	appConfiguration string
	baseURL          string
	userAgent        string
	label            string
	concurrency      int
	timeout          time.Duration
}

// ClientOption is a function that sets options to *Client.
type ClientOption func(o *Client)

// NewClient creates and returns a new Client.
func NewClient(appConfiguration string, cred auth.Credential, options ...ClientOption) *Client {
	c := &Client{
		cred:             cred,
		appConfiguration: appConfiguration,
		baseURL:          strings.Replace(baseURL, "{config}", appConfiguration, 1),
		userAgent:        "azcfg/" + version.Version(),
		concurrency:      defaultConcurrency,
		timeout:          defaultTimeout,
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

// AppConfiguration returns the target Aoo Configuration set on
// the Client.
func (c Client) AppConfiguration() string {
	return c.appConfiguration
}

// Options for client operations.
type Options struct {
	Label string
}

// Option is a function that sets options for client operations.
type Option func(o *Options)

// Get settings (key-values) by names.
func (c Client) GetSettings(keys []string, options ...Option) (map[string]Setting, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	return c.getSettings(ctx, keys, options...)
}

// get a setting.
func (c Client) Get(ctx context.Context, key string, options ...Option) (Setting, error) {
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}

	u := fmt.Sprintf("%s/kv/%s?api-version=%s", c.baseURL, key, apiVersion)
	if len(opts.Label) > 0 {
		u += "&label=" + opts.Label
	}

	header := http.Header{
		"User-Agent": []string{c.userAgent},
	}

	var authHeader string
	if c.cred != nil {
		if c.cred.Scope() != auth.ScopeAppConfig {
			c.cred.SetScope(auth.ScopeAppConfig)
		}
		token, err := c.cred.Token(ctx)
		if err != nil {
			return Setting{}, err
		}
		authHeader = "Bearer " + token.AccessToken
	} else {
		// Create auth header value credential and secret.
		// Add this functionality further on.
		authHeader = ""
	}
	header.Add("Authorization", authHeader)

	var b []byte
	if err := retry.Do(ctx, func() error {
		var err error
		b, err = request.Do(ctx, c.c, header, http.MethodGet, u)
		if err != nil {
			if errors.Is(err, request.ErrNotFound) {
				err = fmt.Errorf("setting %s: %w", key, err)
			}
			return err
		}
		return nil
	}, func(o *retry.Policy) {
		o.Retry = shouldRetry
	}); err != nil {
		return Setting{}, err
	}

	var setting Setting
	if err := json.Unmarshal(b, &setting); err != nil {
		return setting, err
	}

	return setting, nil
}

// settingResult contains result from retreiving settings. Should
// be used with a channel for handling results and errors.
type settingResult struct {
	key     string
	setting Setting
	err     error
}

// getSettings gets settings by the provided keys and returns them as a map[string]Setting
// where setting key is the key.
func (c Client) getSettings(ctx context.Context, keys []string, options ...Option) (map[string]Setting, error) {
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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
					if err != nil && !errors.Is(err, request.ErrNotFound) {
						sr.err = err
						srCh <- sr
						cancel()
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

// WithLabel sets label to target the client against.
func WithLabel(label string) ClientOption {
	return func(o *Client) {
		o.label = label
	}
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

// shouldRetry contains retry policy for setting requests.
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

package keyvault

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/KarlGW/azcfg/internal/errs"
)

const (
	// baseURL is the base URL for Azure Key Vault in the Azure Public Cloud.
	baseURL = "https://{vault}.vault.azure.net"
	// defaultConcurrency specifies how many concurrent calls at a time the
	// client may perform.
	defaultConcurrency = 10
	// defaultTimeout specifies the default timeout for all calls.
	defaultTimeout = time.Millisecond * 1000 * 10
)

// keyvaultClient is the interface that wraps around method GetSecret from the Azure SDK for Go - Azure Key Vault Client
// at: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets
type keyvaultClient interface {
	// GetSecret - Get a secret from Azure Key Vault.
	GetSecret(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// Client contains the methods to call the Azure Key Vault API and the
// base settings for how to handle these calls.
type Client struct {
	client      keyvaultClient
	concurrency int
	timeout     time.Duration
}

// ClientOptions contains settings for the Key Vault client.
type ClientOptions struct {
	Concurrency int
	Timeout     time.Duration
}

// NewClient creates and returns a new Client.
func NewClient(vault string, cred azcore.TokenCredential, opts *ClientOptions) (*Client, error) {
	if opts == nil {
		opts = &ClientOptions{
			Concurrency: defaultConcurrency,
			Timeout:     defaultTimeout,
		}
	}

	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}

	client, err := azsecrets.NewClient(strings.Replace(baseURL, "{vault}", vault, 1), cred, nil)
	if err != nil {
		return nil, err
	}
	return &Client{
		client:      client,
		concurrency: opts.Concurrency,
		timeout:     opts.Timeout,
	}, nil
}

// GetSecrets calls the Azure Key Vault API for secrets based on their
// names. It performs these calls concurrently with maximum concurrent
// calls based on provided client options.
func (c Client) GetSecrets(names []string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	return c.receiveSecrets(c.getSecrets(ctx, names), len(names))
}

// secretResult contains the results from a GetSecret call.
type secretResult struct {
	name  string
	value string
	err   error
}

// getSecrets performs calls to the target Azure Key Vault concurrently. It
// returns a channel that contains the results.
func (c Client) getSecrets(ctx context.Context, names []string) <-chan secretResult {
	namesCh := make(chan string)
	srCh := make(chan secretResult)

	go func() {
		for i := 0; i < len(names); i++ {
			namesCh <- names[i]
		}
		close(namesCh)
	}()

	for i := 1; i < c.concurrency; i++ {
		go func() {
			for secret := range namesCh {
				sr := secretResult{name: secret}
				s, err := c.client.GetSecret(ctx, secret, "", nil)
				if err != nil {
					var rerr *azcore.ResponseError
					if errors.As(err, &rerr) {
						if rerr.StatusCode == http.StatusNotFound {
							srCh <- sr
							return
						}
						err = parseError(rerr)
					}
					sr.err = err
					srCh <- sr
					return
				}
				sr.value = *s.SecretBundle.Value
				srCh <- sr
			}
		}()
	}
	return srCh
}

// receiveSecrets receives secretResult on a channel. Returns a map[string]string with
// containing the secrets as a key (name)/value pairs.
func (c Client) receiveSecrets(srCh <-chan secretResult, length int) (map[string]string, error) {
	out := make(map[string]string, length)
	var errs errs.Errors
	for i := 0; i < length; i++ {
		sr := <-srCh
		if sr.err != nil {
			errs = append(errs, sr.err)
		} else {
			out[sr.name] = sr.value
		}
	}
	if len(errs) != 0 {
		return out, errs
	}
	return out, nil
}

// responseError represents the error response body from the Azure Key Vault
// API.
type responseError struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

// parseError takes error of type *azcore.ResponseError and returns
// a new error based on the error message from the Azure Key Vault API.
func parseError(e *azcore.ResponseError) error {
	var re responseError
	b, err := io.ReadAll(e.RawResponse.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, &re); err != nil {
		return err
	}
	return errors.New(re.Error.Message)
}

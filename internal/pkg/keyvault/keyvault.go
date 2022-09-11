package keyvault

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
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
func NewClient(vault string, cred azcore.TokenCredential, opts *ClientOptions) *Client {
	if opts == nil {
		opts = &ClientOptions{
			Concurrency: defaultConcurrency,
			Timeout:     defaultTimeout,
		}
	}

	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}

	client := azsecrets.NewClient(strings.Replace(baseURL, "{vault}", vault, 1), cred, nil)
	return &Client{
		client:      client,
		concurrency: opts.Concurrency,
		timeout:     opts.Timeout,
	}
}

// GetSecrets calls the Azure Key Vault API for secrets based on their
// names. It performs these calls concurrently with maximum concurrent
// calls based on provided client options.
func (c Client) GetSecrets(names []string) (map[string]string, error) {
	secrets := make(chan string)
	results := make(chan result)

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	for w := 1; w <= c.concurrency; w++ {
		go c.getSecretWorker(ctx, secrets, results)
	}

	go func() {
		for i := 0; i < len(names); i++ {
			secrets <- names[i]
		}
	}()

	out := make(map[string]string, len(names))
	errorMessages := make([]string, 0)
	for i := 0; i < len(names); i++ {
		secret := <-results
		if secret.err != nil {
			errorMessages = append(errorMessages, secret.err.Error())
		} else {
			out[secret.name] = secret.value
		}
	}

	var err error
	if len(errorMessages) != 0 {
		errMsg := strings.Join(errorMessages, ", ")
		err = errors.New(errMsg)
	}

	return out, err
}

// result contains the results from a GetSecret call.
type result struct {
	name  string
	value string
	err   error
}

// getSecretWorker is the worker that performs calls to Azure Key Vault concurrently.
// It receives secret names from the secrets channel (string), and sends the results
// to the results channel (result).
func (c Client) getSecretWorker(ctx context.Context, secrets <-chan string, results chan<- result) {
	for secret := range secrets {
		sr := &result{name: secret}
		s, err := c.client.GetSecret(ctx, secret, "", nil)
		if err != nil {
			sr.err = err
			results <- *sr
			return
		}
		sr.value = *s.SecretBundle.Value
		results <- *sr
	}
}

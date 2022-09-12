package azcfg

import (
	"errors"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

const (
	// defaultConcurrency is the default amount of concurrent calls
	// to the Azure Key Vault Secret API.
	defaultConcurrency = 10
	// defaultTimeout is the default timeout for the requests
	// for the secrets.
	defaultTimeout = time.Millisecond * 1000 * 10
)

// envKeyVault contains environment variables to check for
// Azure Key Vault name.
var (
	envKeyVault = []string{
		"AZURE_KEY_VAULT",
		"AZURE_KEY_VAULT_NAME",
		"AZURE_KEYVAULT",
		"AZURE_KEYVAULT_NAME",
	}
)

// opts sets and contains options for the package.
var (
	defaultOpts = options{
		client: client{
			credential:  nil,
			vault:       "",
			concurrency: defaultConcurrency,
			timeout:     defaultTimeout,
		},
	}

	opts = &options{
		client: client{
			credential:  defaultOpts.client.credential,
			vault:       defaultOpts.client.vault,
			concurrency: defaultOpts.client.concurrency,
			timeout:     defaultOpts.client.timeout,
		},
	}
)

// options contains options for the package.
type options struct {
	client         client
	externalClient KeyVaultClient
}

// client contains options for the Key Vault client.
type client struct {
	credential  azcore.TokenCredential
	vault       string
	concurrency int
	timeout     time.Duration
}

// ClientOptions contains options for the Key Vault client.
type ClientOptions struct {
	Credential  azcore.TokenCredential
	Vault       string
	Concurrency int
	Timeout     time.Duration
}

// SetClientOptions sets client options from the provided ClientOptions.
func SetClientOptions(o *ClientOptions) {
	if o == nil {
		return
	}

	if o.Concurrency == 0 {
		o.Concurrency = defaultConcurrency
	}

	if o.Timeout == 0 {
		o.Timeout = defaultTimeout
	}

	opts.client = client{
		credential:  o.Credential,
		vault:       o.Vault,
		concurrency: o.Concurrency,
		timeout:     o.Timeout,
	}
}

// SetCredentials sets credentials to be used for requests to Azure Key Vault.
// Use when credential reuse is desireable.
func SetCredential(cred azcore.TokenCredential) {
	opts.client.credential = cred
}

// SetVault sets the Azure Key Vault to query for
// secrets.
func SetVault(vault string) {
	opts.client.vault = vault
}

// SetConcurrency sets amount of concurrent calls to
// Azure Key Vault.
func SetConcurrency(c int) {
	opts.client.concurrency = c
}

// SetTimeout sets the total timeout for the requests
// to Azure Key Vault.
func SetTimeout(d time.Duration) {
	opts.client.timeout = d
}

// SetExternalClient sets an external alternative client to
// use for Azure Key Vault requests. Must implement
// keyvaultClient.
func SetExternalClient(client KeyVaultClient) {
	opts.externalClient = client
}

// getVault checks the environment if any of the variables AZURE_KEY_VAULT,
// AZURE_KEY_VAULT_NAME, AZURE_KEYVAULT or AZURE_KEYVAULT_NAME is set.
func getVaultFromEnvironment() (string, error) {
	for _, v := range envKeyVault {
		if len(os.Getenv(v)) != 0 {
			return os.Getenv(v), nil
		}
	}
	return "", errors.New("a Key Vault name must be set")
}

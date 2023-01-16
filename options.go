package azcfg

import (
	"errors"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// envKeyVault contains environment variables to check for
// Azure Key Vault name.
var (
	envKeyVault = [4]string{
		"AZURE_KEY_VAULT",
		"AZURE_KEY_VAULT_NAME",
		"AZURE_KEYVAULT",
		"AZURE_KEYVAULT_NAME",
	}
)

// opts sets and contains options for the package.
var (
	defaultOpts = options{
		secrets:     &secrets{},
		concurrency: 10,
		timeout:     time.Millisecond * 1000 * 10,
	}

	opts = &options{
		secrets:     defaultOpts.secrets,
		concurrency: defaultOpts.concurrency,
		timeout:     defaultOpts.timeout,
	}
)

// options contains options and settings for the package.
type options struct {
	secrets         *secrets
	azureCredential azcore.TokenCredential
	concurrency     int
	timeout         time.Duration
}

// secrets contains options for the Secrets client.
type secrets struct {
	client SecretsClient
	vault  string
}

// Options for package and Parse.
type Options struct {
	Secrets         *SecretsOptions
	AzureCredential azcore.TokenCredential
	Concurrency     int
	Timeout         time.Duration
}

// SecretsOptions contains options for secrets
// and secrets client.
type SecretsOptions struct {
	Client SecretsClient
	Vault  string
}

// SetOptions sets package level options.
func SetOptions(options *Options) *options {
	if options == nil {
		return opts
	}

	if options.AzureCredential != nil {
		opts.azureCredential = options.AzureCredential
	}

	if options.Concurrency != 0 {
		opts.concurrency = options.Concurrency
	}

	if options.Timeout != 0 {
		opts.timeout = options.Timeout
	}

	if options.Secrets != nil {
		if options.Secrets.Client != nil {
			opts.secrets.client = options.Secrets.Client
		}

		if len(options.Secrets.Vault) != 0 {
			opts.secrets.vault = options.Secrets.Vault
		}
	}

	return opts
}

// SetSecretsClient sets an alternative client for Azure Key Vault requests.
// Must implement SecretsClient.
func SetSecretsClient(c SecretsClient) *options {
	opts.secrets.client = c
	return opts
}

// SetSecretsVault sets the Azure Key Vault to query for
// secrets.
func SetSecretsVault(vault string) *options {
	opts.secrets.vault = vault
	return opts
}

// SetAzureCredential sets credentials to be used for requests to Azure Key Vault.
// Use when credential reuse is desireable.
func SetAzureCredential(cred azcore.TokenCredential) *options {
	opts.azureCredential = cred
	return opts
}

// SetConcurrency sets amount of concurrent calls for fetching secrets.
func SetConcurrency(c int) *options {
	opts.concurrency = c
	return opts
}

// SetTimeout sets the total timeout for the requests for fetching
// secrets.
func SetTimeout(d time.Duration) *options {
	opts.timeout = d
	return opts
}

// getSecretsVault checks the environment if any of the variables AZURE_KEY_VAULT,
// AZURE_KEY_VAULT_NAME, AZURE_KEYVAULT or AZURE_KEYVAULT_NAME is set.
func getSecretsVaultFromEnvironment() (string, error) {
	for _, v := range envKeyVault {
		if len(os.Getenv(v)) != 0 {
			return os.Getenv(v), nil
		}
	}
	return "", errors.New("a Key Vault name must be set")
}

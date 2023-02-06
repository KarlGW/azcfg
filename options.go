package azcfg

import (
	"errors"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/KarlGW/azcfg/internal/pkg/keyvault"
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

// pkgOpts contains options for the package.
var (
	defaultConcurrency = 10
	defaultTimeout     = time.Millisecond * 1000 * 10

	pkgOpts = &options{
		secrets:     &secrets{},
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
)

// SecretsClient is the interface that wraps around method GetSecrets.
type SecretsClient interface {
	GetSecrets(names []string) (map[string]string, error)
}

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

// SetSecretsClient sets an alternative client for Azure Key Vault requests.
// Must implement SecretsClient.
func (o *options) SetSecretsClient(client SecretsClient) *options {
	return SetSecretsClient(client)
}

// SetSecretsVault sets the Azure Key Vault to query for
// secrets.
func (o *options) SetSecretsVault(vault string) *options {
	return SetSecretsVault(vault)
}

// SetAzureCredential sets credentials to be used for requests to Azure Key Vault.
// Use when credential reuse is desireable.
func (o *options) SetAzureCredential(cred azcore.TokenCredential) *options {
	return SetAzureCredential(cred)
}

// SetConcurrency sets amount of concurrent calls for fetching secrets.
func (o *options) SetConcurrency(c int) *options {
	return SetConcurrency(c)
}

// SetTimeout sets the total timeout for the requests for fetching
// secrets.
func (o *options) SetTimeout(d time.Duration) *options {
	return SetTimeout(d)
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
func SetOptions(o *Options) {
	if o == nil {
		return
	}
	pkgOpts = evalOptions(*o)
}

// SetSecretsClient sets an alternative client for Azure Key Vault requests.
// Must implement SecretsClient.
func SetSecretsClient(client SecretsClient) *options {
	pkgOpts.secrets.client = client
	return pkgOpts
}

// SetSecretsVault sets the Azure Key Vault to query for
// secrets.
func SetSecretsVault(vault string) *options {
	pkgOpts.secrets.vault = vault
	return pkgOpts
}

// SetAzureCredential sets credentials to be used for requests to Azure Key Vault.
// Use when credential reuse is desireable.
func SetAzureCredential(cred azcore.TokenCredential) *options {
	pkgOpts.azureCredential = cred
	return pkgOpts
}

// SetConcurrency sets amount of concurrent calls for fetching secrets.
func SetConcurrency(c int) *options {
	pkgOpts.concurrency = c
	return pkgOpts
}

// SetTimeout sets the total timeout for the requests for fetching
// secrets.
func SetTimeout(d time.Duration) *options {
	pkgOpts.timeout = d
	return pkgOpts
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

// evalOptions takes the provide options and checks it against the package level options and returns
// a new options evaluated from them both. The provided options overwrites package level options.
func evalOptions(o ...Options) *options {
	opts := options{
		secrets: &secrets{
			client: pkgOpts.secrets.client,
			vault:  pkgOpts.secrets.vault,
		},
		azureCredential: pkgOpts.azureCredential,
		concurrency:     pkgOpts.concurrency,
		timeout:         pkgOpts.timeout,
	}

	for _, o := range o {
		if o.Secrets != nil {
			if o.Secrets.Client != nil {
				opts.secrets.client = o.Secrets.Client
			}
			if len(o.Secrets.Vault) != 0 {
				opts.secrets.vault = o.Secrets.Vault
			}
		}
		if o.AzureCredential != nil {
			opts.azureCredential = o.AzureCredential
		}
		if o.Concurrency != 0 {
			opts.concurrency = o.Concurrency
		}
		if o.Timeout != 0 {
			opts.timeout = o.Timeout
		}
	}
	return &opts
}

// azureCredentialFunc should returns azcore.TokenCredential and error.
type azureCredentialFunc func() (azcore.TokenCredential, error)

// keyvaultClientFunc should return SecretsClient and error.
type keyvaultClientFunc func(vault string, cred azcore.TokenCredential, options *keyvault.ClientOptions) (SecretsClient, error)

// evalClient takes the to provided *options, azureCredentialFunc and keyvaultClientFunc to
// determine secrets client, azure credential and vault. Creates a SecretsClient if necessary.
func evalClient(o *options, azureCredentialFn azureCredentialFunc, keyvaultClientFn keyvaultClientFunc) (SecretsClient, error) {
	if o == nil {
		o = &options{
			secrets: &secrets{},
		}
	}

	if o.secrets == nil {
		o.secrets = &secrets{}
	}

	if o.secrets.client != nil {
		return o.secrets.client, nil
	}

	var cred azcore.TokenCredential
	if o.azureCredential != nil {
		cred = o.azureCredential
	} else {
		var err error
		cred, err = azureCredentialFn()
		if err != nil {
			return nil, err
		}
	}

	var vault string
	if len(o.secrets.vault) != 0 {
		vault = o.secrets.vault
	} else {
		var err error
		vault, err = getSecretsVaultFromEnvironment()
		if err != nil {
			return nil, err
		}
	}

	return keyvaultClientFn(vault, cred, &keyvault.ClientOptions{
		Concurrency: o.concurrency,
		Timeout:     o.timeout,
	})
}

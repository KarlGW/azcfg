package azcfg

import (
	"errors"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/KarlGW/azcfg/internal/keyvault"
)

var (
	// defaultConcurrency contains the default concurrency for the
	// parser.
	defaultConcurrency = 10
	// defaultTimeout contains the default timeout for the parser.
	defaultTimeout = time.Millisecond * 1000 * 10
)

// Options contains options for a package level Parse operation, and
// options for an instance of Parse created with NewParser.
type Options struct {
	// Client is the client used to retrieve secrets. Used to override the default
	// Client.
	Client Client
	// Credential is the credential to be used with the Client. Used to override
	// the default method of aquiring credentials.
	Credential azcore.TokenCredential
	// Vault is the name of the vault containing secrets. Used to override the
	// default method of aquiring target vault.
	Vault string
	// Timeout is the total timeout for retrieval of secrets. Defaults to 10 seconds.
	Timeout time.Duration
	// Concurrency is the amount of secrets that will be retrieved concurrently.
	// Defaults to 10.
	Concurrency int
}

// SetOptions sets package level options.
func SetOptions(o *Options) *Parser {
	if o == nil {
		return parser
	}
	return evalOptions(parser, *o)
}

// SetClient sets an alternative client for Azure Key Vault requests.
// Must implement Client.
func SetClient(client Client) *Parser {
	return parser.SetClient(client)
}

// SetCredential sets credential to be used for requests to Azure Key Vault.
// Use when credential reuse is desireable.
func SetCredential(cred azcore.TokenCredential) *Parser {
	return parser.SetCredential(cred)
}

// SetVault sets the Azure Key Vault to query for secrets.
func SetVault(vault string) *Parser {
	return parser.SetVault(vault)
}

// SetConcurrency sets amount of concurrent calls for fetching secrets.
func SetConcurrency(c int) *Parser {
	return parser.SetConcurrency(c)
}

// SetTimeout sets the total timeout for the requests for fetching secrets.
func SetTimeout(d time.Duration) *Parser {
	return parser.SetTimeout(d)
}

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

// getVaultFromEnvironment checks the environment if any of the variables AZURE_KEY_VAULT,
// AZURE_KEY_VAULT_NAME, AZURE_KEYVAULT or AZURE_KEYVAULT_NAME is set.
func getVaultFromEnvironment() (string, error) {
	for _, v := range envKeyVault {
		if len(os.Getenv(v)) != 0 {
			return os.Getenv(v), nil
		}
	}
	return "", errors.New("a Key Vault name must be set")
}

// evalOptions takes the provided *Parser and checks it against the provided ...Options and
// overrides the settings of the *Parser if they exist in the provided ...Options.
func evalOptions(p *Parser, o ...Options) *Parser {
	for _, o := range o {
		if o.Client != nil {
			p.client = o.Client
		}
		if len(o.Vault) != 0 {
			p.vault = o.Vault
		}

		if o.Credential != nil {
			p.credential = o.Credential
		}
		if o.Concurrency != 0 {
			p.concurrency = o.Concurrency
		}
		if o.Timeout != 0 {
			p.timeout = o.Timeout
		}
	}
	return p
}

// azureCredentialFunc should returns azcore.TokenCredential and error.
type azureCredentialFunc func() (azcore.TokenCredential, error)

// newAzureCredential calls azidentity.NewDefaultAzureCredential.
func newAzureCredential() (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

// keyvaultClientFunc should return Client and error.
type keyvaultClientFunc func(vault string, cred azcore.TokenCredential, options *keyvault.ClientOptions) (Client, error)

// newKeyVaultClient calls keyvault.NewClient.
func newKeyvaultClient(vault string, cred azcore.TokenCredential, options *keyvault.ClientOptions) (Client, error) {
	return keyvault.NewClient(vault, cred, options)
}

// evalClient takes the to provided *Parser, azureCredentialFunc and keyvaultClientFunc to
// determine secrets client, azure credential and vault. Creates a Client if necessary.
func evalClient(p *Parser, azureCredentialFn azureCredentialFunc, keyvaultClientFn keyvaultClientFunc) (*Parser, error) {
	var err error
	if p == nil {
		return nil, errors.New("a *Parser must be provided")
	}

	if p.client != nil {
		return p, nil
	}

	if p.credential == nil {
		p.credential, err = azureCredentialFn()
		if err != nil {
			return p, err
		}
	}

	if len(p.vault) == 0 {
		p.vault, err = getVaultFromEnvironment()
		if err != nil {
			return p, err
		}
	}

	client, err := keyvaultClientFn(p.vault, p.credential, &keyvault.ClientOptions{
		Concurrency: p.concurrency,
		Timeout:     p.timeout,
	})
	if err != nil {
		return p, err
	}

	p.client = client
	return p, nil
}

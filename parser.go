package azcfg

import (
	"errors"
	"os"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/identity"
	"github.com/KarlGW/azcfg/internal/secret"
)

// client is the interface that wraps around method Get.
type client interface {
	Get(names ...string) (map[string]secret.Secret, error)
}

// parser contains all the necessary values and settings for calls to Parse.
type parser struct {
	cl          client
	cred        auth.Credential
	timeout     time.Duration
	concurrency int
	vault       string
}

// Options contains options for the Parser.
type Options struct {
	// Credential is the credential to be used with the Client. Used to override
	// the default method of aquiring credentials.
	Credential auth.Credential
	// Timeout is the total timeout for retrieval of secrets. Defaults to 10 seconds.
	Timeout time.Duration
	// Concurrency is the amount of secrets that will be retrieved concurrently.
	// Defaults to 10.
	Concurrency int
	// Vault is the name of the vault containing secrets. Used to override the
	// default method of aquiring target vault.
	Vault string
}

// Option is a function that sets Options.
type Option func(o *Options)

// NewParser creates and returns a *Parser. With no options provided
// it will have default settings for timeout and concurrency.
func NewParser(options ...Option) (*parser, error) {
	p := &parser{
		timeout:     time.Millisecond * 1000 * 10,
		concurrency: 10,
		vault:       vaultFromEnvironment(),
	}
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}

	if opts.Credential != nil {
		p.cred = opts.Credential
	} else {
		var err error
		p.cred, err = setupCredential()
		if err != nil {
			return nil, err
		}
	}

	if opts.Concurrency > 0 {
		p.concurrency = opts.Concurrency
	}
	if opts.Timeout > 0 {
		p.timeout = opts.Timeout
	}
	if len(opts.Vault) > 0 {
		p.vault = opts.Vault
	}

	if len(p.vault) == 0 {
		return nil, errors.New("a vault must be set")
	}

	cl := secret.NewClient(
		p.vault,
		p.cred,
		secret.WithTimeout(p.timeout),
		secret.WithConcurrency(p.concurrency),
	)
	p.cl = cl

	return p, nil
}

// Parse secrets from an Azure Key Vault into a struct.
func (p *parser) Parse(v any) error {
	return parse(v, p.cl)
}

// WithCredential sets the provided credential to the parser.
func WithCredential(cred auth.Credential) Option {
	return func(o *Options) {
		o.Credential = cred
	}
}

// WithVault sets the vault for the parser.
func WithVault(vault string) Option {
	return func(o *Options) {
		o.Vault = vault
	}
}

// WithConcurrency sets the concurrency of the parser.
func WithConcurrency(c int) Option {
	return func(o *Options) {
		o.Concurrency = c
	}
}

// WithTimeout sets the timeout of the parser.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.Timeout = d
	}
}

var (
	// Resource for Azure Key Vault requests.
	resource = "https://vault.azure.net"
	// Scope for Azure Key Vault requests.
	scope = resource + "/.default"
)

// setupCredential checks the environment for
func setupCredential() (auth.Credential, error) {
	// First attempt with Service Principal, then proceed to managed identity.
	tenantID, clientID, clientSecret := os.Getenv("AZCFG_TENANT_ID"), os.Getenv("AZCFG_CLIENT_ID"), os.Getenv("AZCFG_CLIENT_SECRET")
	if len(tenantID) > 0 && len(clientID) > 0 && len(clientSecret) > 0 {
		return identity.NewClientSecretCredential(tenantID, clientID, clientSecret, identity.WithScope(scope))
	} else {
		return identity.NewManagedIdentityCredential(identity.WithClientID(clientID), identity.WithScope(resource))
	}
}

var (
	// envKeyVault contains environment variable names for Key Vault.
	envKeyVault = [4]string{
		"AZCFG_KEY_VAULT",
		"AZCFG_KEY_VAULT_NAME",
		"AZCFG_KEYVAULT",
		"AZCFG_KEYVAULT_NAME",
	}
)

// vaultFromEnvironment checks the environment if any of the variables AZCFG_KEY_VAULT,
// AZCFG_KEY_VAULT_NAME, AZCFG_KEYVAULT or AZCFG_KEYVAULT_NAME is set.
func vaultFromEnvironment() string {
	for _, v := range envKeyVault {
		if len(os.Getenv(v)) != 0 {
			return os.Getenv(v)
		}
	}
	return ""
}

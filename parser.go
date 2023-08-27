package azcfg

import (
	"errors"
	"os"
	"time"

	"github.com/KarlGW/azcfg/internal/auth"
	"github.com/KarlGW/azcfg/internal/secret"
)

var (
	// defaultConcurrency contains the default concurrency for the
	// parser.
	defaultConcurrency = 10
	// defaultTimeout contains the default timeout for the parser.
	defaultTimeout = time.Millisecond * 1000 * 10
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
func NewParser(options ...Option) *parser {
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Credential == nil {
		// Temp. This should create credentials with the default provider.
		opts.Credential = &auth.AdaptorCredential{}
	}

	p := &parser{
		cred:        opts.Credential,
		timeout:     opts.Timeout,
		concurrency: opts.Concurrency,
		vault:       opts.Vault,
	}

	cl := secret.NewClient(
		p.vault,
		p.cred,
		secret.WithTimeout(p.timeout),
		secret.WithConcurrency(p.concurrency),
	)
	p.cl = cl

	return p
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

var (
	envKeyVault = [4]string{
		"AZCFG_AZURE_KEY_VAULT",
		"AZCFG_AZURE_KEY_VAULT_NAME",
		"AZCFG_AZURE_KEYVAULT",
		"AZCFG_AZURE_KEYVAULT_NAME",
	}
)

// vaultFromEnvironment checks the environment if any of the variables AZURE_KEY_VAULT,
// AZURE_KEY_VAULT_NAME, AZURE_KEYVAULT or AZURE_KEYVAULT_NAME is set.
func vaultFromEnvironment() (string, error) {
	for _, v := range envKeyVault {
		if len(os.Getenv(v)) != 0 {
			return os.Getenv(v), nil
		}
	}
	return "", errors.New("a Key Vault name must be set")
}

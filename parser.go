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
	// TenantID of the Service Principal with access to target Key Vault.
	TenantID string
	// ClientID of the Service Principal or user assigned managed identity with access to target Key Vault.
	ClientID string
	// ClientSecret of the Service Principal with access to target Key Vault.
	ClientSecret string
	// UseManagedIdentity set to use a managed identity. To use a user assigned managed identity, use
	// together with ClientID.
	UseManagedIdentity bool
}

// Option is a function that sets Options.
type Option func(o *Options)

// NewParser creates and returns a *Parser. With no options provided
// it will have default settings for timeout and concurrency.
func NewParser(options ...Option) (*parser, error) {
	p := &parser{
		timeout:     time.Second * 5,
		concurrency: 10,
	}
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}

	var err error
	p.cred, err = setupCredential(opts)
	if err != nil {
		return nil, err
	}

	p.vault = setupVault(opts.Vault)
	if len(p.vault) == 0 {
		return nil, errors.New("a vault must be set")
	}

	if opts.Concurrency > 0 {
		p.concurrency = opts.Concurrency
	}
	if opts.Timeout > 0 {
		p.timeout = opts.Timeout
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

// WithClientSecretCredential sets the parser to use client credential with
// a secret (client secret credential) for the Key Vault.
func WithClientSecretCredential(tenantID, clientID, clientSecret string) Option {
	return func(o *Options) {
		o.TenantID = tenantID
		o.ClientID = clientID
		o.ClientSecret = clientSecret
	}
}

// WithManagedIdentity sets the parser to use a managed identity
// for credentials for the Key Vault.
func WithManagedIdentity(clientID ...string) Option {
	return func(o *Options) {
		if len(clientID) > 0 {
			o.ClientID = clientID[0]
		}
		o.UseManagedIdentity = true
	}
}

const (
	// Resource for Azure Key Vault requests.
	resource = "https://vault.azure.net"
	// Scope for Azure Key Vault requests.
	scope = resource + "/.default"
)

// setupCredential configures credential based on the provided
// options.
func setupCredential(options Options) (auth.Credential, error) {
	if options.Credential != nil {
		return options.Credential, nil
	}
	var cred auth.Credential
	var err error
	if len(options.TenantID) == 0 && len(options.ClientID) == 0 && len(options.ClientSecret) == 0 && !options.UseManagedIdentity {
		cred, err = credentialFromEnvironment()
	} else if len(options.TenantID) > 0 && len(options.ClientID) > 0 && len(options.ClientSecret) > 0 && !options.UseManagedIdentity {
		cred, err = newClientCredential(options.TenantID, options.ClientID, options.ClientSecret)
	} else if options.UseManagedIdentity {
		cred, err = newManagedIdentityCredential(options.ClientID)
	}
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errors.New("could not determine credentials and authentication method")
	}
	return cred, err
}

// credentialFromEnvironment gets credential details from environment variables.
func credentialFromEnvironment() (auth.Credential, error) {
	tenantID, clientID, clientSecret := os.Getenv("AZCFG_TENANT_ID"), os.Getenv("AZCFG_CLIENT_ID"), os.Getenv("AZCFG_CLIENT_SECRET")
	if len(tenantID) > 0 && len(clientID) > 0 && len(clientSecret) > 0 {
		return newClientCredential(tenantID, clientID, clientSecret)
	} else {
		return newManagedIdentityCredential(clientID)
	}
}

// setupVault configures target Key Vault based on the provided parameters.
func setupVault(vault string) string {
	if len(vault) == 0 {
		return os.Getenv("AZCFG_KEYVAULT_NAME")
	} else {
		return vault
	}
}

var newClientCredential = func(tenantID, clientID, clientSecret string) (auth.Credential, error) {
	return identity.NewClientCredential(tenantID, clientID, identity.WithSecret(clientSecret), identity.WithScope(scope))
}

var newManagedIdentityCredential = func(clientID string) (auth.Credential, error) {
	return identity.NewManagedIdentityCredential(identity.WithClientID(clientID), identity.WithScope(resource))
}

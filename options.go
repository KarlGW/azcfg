package azcfg

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/KarlGW/azcfg/auth"
)

// Options contains options for the Parser.
type Options struct {
	// Credential is the credential to be used with the Client. Used to override
	// the default method of aquiring credentials.
	Credential auth.Credential
	// SecretClient is a client used to retrieve secrets.
	SecretClient secretClient
	// SettingClient is a client used to retrieve settings.
	SettingClient settingClient
	// KeyVault is the name of the Key Vault containing secrets. Used to override the
	// default method of aquiring target Key Vault.
	KeyVault string
	// AppConfiguration is the name of the App Configuration containing settibgs. Used to override the
	// default method of aquiring target App Configuration.
	AppConfiguration string
	// Label for setting in an Azure App Configuration.
	Label string
	// TenantID of the Service Principal with access to target Key Vault.
	TenantID string
	// ClientID of the Service Principal or user assigned managed identity with access to target Key Vault.
	ClientID string
	// ClientSecret of the Service Principal with access to target Key Vault.
	ClientSecret string
	// Certificates for the Service Principal with access to target Key Vault.
	Certificates []*x509.Certificate
	// Assertion is an assertion function for a client assertion credential.
	Assertion func() (string, error)
	// PrivateKey to be used with the certificates for the Service Principal with access to target Key Vault.
	PrivateKey *rsa.PrivateKey
	// RetryPolicy is the retry policy for the clients of the parser.
	RetryPolicy RetryPolicy
	// Concurrency is the amount of secrets that will be retrieved concurrently.
	// Defaults to 10.
	Concurrency int
	// Timeout is the total timeout for retrieval of secrets. Defaults to 10 seconds.
	Timeout time.Duration
	// UseManagedIdentity set to use a managed identity. To use a user assigned managed identity, use
	// together with ClientID.
	UseManagedIdentity bool
	// Context for the parser. By default a context is created based on the timeout set on the parser.
	Context context.Context
}

// Option is a function that sets Options.
type Option func(o *Options)

// WithCredential sets the provided credential to the parser.
func WithCredential(cred auth.Credential) Option {
	return func(o *Options) {
		o.Credential = cred
	}
}

// WithKeyVault sets the Key Vault for the parser.
func WithKeyVault(keyVault string) Option {
	return func(o *Options) {
		o.KeyVault = keyVault
	}
}

// WithAppConfiguration sets the App Configuration for the parser.
func WithAppConfiguration(appConfiguration string) Option {
	return func(o *Options) {
		o.AppConfiguration = appConfiguration
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

// WithClientCertificateCredential sets the parser to use client credential with
// a certificate (client certificate credential) for the Key Vault.
func WithClientCertificateCredential(tenantID, clientID string, certificates []*x509.Certificate, key *rsa.PrivateKey) Option {
	return func(o *Options) {
		o.TenantID = tenantID
		o.ClientID = clientID
		o.Certificates = certificates
		o.PrivateKey = key
	}
}

// WithClientAssertionCredential sets the parser to use client credential with an assertion.
// The assertion should be a function that returns a JWT from an identity provider.
func WithClientAssertionCredential(tenantID, clientID string, assertion func() (string, error)) Option {
	return func(o *Options) {
		o.TenantID = tenantID
		o.ClientID = clientID
		o.Assertion = assertion
	}
}

// WithManagedIdentity sets the parser to use a managed identity
// for credentials for the Key Vault.
func WithManagedIdentity(clientID ...string) Option {
	return func(o *Options) {
		o.UseManagedIdentity = true
		if len(clientID) > 0 {
			o.ClientID = clientID[0]
		}
	}
}

// WithLabel sets the label for settings in App Configuration.
func WithLabel(label string) Option {
	return func(o *Options) {
		o.Label = label
	}
}

// WithSecretClient sets the client for secret retrieval.
func WithSecretClient(c secretClient) Option {
	return func(o *Options) {
		o.SecretClient = c
	}
}

// WithSettingClient sets the client for setting retreival.
func WithSettingClient(c settingClient) Option {
	return func(o *Options) {
		o.SettingClient = c
	}
}

// WithRetryPolicy sets the retry policy for the parser.
func WithRetryPolicy(r RetryPolicy) Option {
	return func(o *Options) {
		o.RetryPolicy = r
	}
}

// WithContext sets the context for the parser.
func WithContext(ctx context.Context) Option {
	return func(o *Options) {
		o.Context = ctx
	}
}

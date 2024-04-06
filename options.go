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
	// Credential is the credential to be used with the Client.
	Credential auth.Credential
	// SecretClient is a client used to retrieve secrets.
	SecretClient secretClient
	// SettingClient is a client used to retrieve settings.
	SettingClient settingClient
	// Context for parsing. By default a context is created based on
	// the timeout set on the parser. Only applies when used together
	// with the Parse function or parser Parse method.
	Context context.Context
	// KeyVault is the name of the Key Vault containing secrets.
	KeyVault string
	// AppConfiguration is the name of the App Configuration containing
	// settings.
	AppConfiguration string
	// Label for setting in an Azure App Configuration.
	Label string
	// TenantID of the Service Principal with access to target
	// Key Vault and/or App Configuration.
	TenantID string
	// ClientID of the Service Principal or user assigned managed identity
	// with access to target Key Vault and/or App Configuration.
	ClientID string
	// ClientSecret of the Service Principal with access to target Key Vault
	// and/or App Configuration.
	ClientSecret string
	// Certificates for the Service Principal with access to target Key Vault
	// and/or App Configuration.
	Certificates []*x509.Certificate
	// Assertion is an assertion function for a client assertion credential.
	Assertion func() (string, error)
	// PrivateKey to be used with the certificates for the Service Principal
	// with access to target Key Vault and/or App Configuration.
	PrivateKey *rsa.PrivateKey
	// RetryPolicy is the retry policy for the clients of the parser.
	RetryPolicy RetryPolicy
	// Concurrency is the amount of secrets/settings that will be retrieved
	// concurrently. Defaults to 10.
	Concurrency int
	// Timeout is the total timeout for retrieval of secrets.
	// Defaults to 10 seconds.
	Timeout time.Duration
	// ManagedIdentity sets the use of a managed identity. To use a user assigned
	// managed identity, use together with ClientID.
	ManagedIdentity bool
	// AzureCLICredential sets the use of Azure CLI credentials.
	AzureCLICredential bool
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
// a secret (client secret credential).
func WithClientSecretCredential(tenantID, clientID, clientSecret string) Option {
	return func(o *Options) {
		o.TenantID = tenantID
		o.ClientID = clientID
		o.ClientSecret = clientSecret
	}
}

// WithClientCertificateCredential sets the parser to use client credential with
// a certificate (client certificate credential).
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

// WithManagedIdentity sets the parser to use a managed identity.
func WithManagedIdentity(clientID ...string) Option {
	return func(o *Options) {
		o.ManagedIdentity = true
		if len(clientID) > 0 {
			o.ClientID = clientID[0]
		}
	}
}

// WithAzureCLICredential sets the parser to use Azure CLI credential.
func WithAzureCLICredential() Option {
	return func(o *Options) {
		o.AzureCLICredential = true
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

// WithContext sets the context for the call to Parse.
func WithContext(ctx context.Context) Option {
	return func(o *Options) {
		o.Context = ctx
	}
}

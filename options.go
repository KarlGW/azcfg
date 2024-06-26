package azcfg

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"strconv"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
)

const (
	// azcfgCloud is the environment variable for the (azure) cloud.
	azcfgCloud = "AZCFG_CLOUD"
	// azcfgConcurrency is the environment variable for the concurrency.
	azcfgConcurrency = "AZCFG_CONCURRENCY"
	// azcfgTimeout is the environment variable for the timeout.
	azcfgTimeout = "AZCFG_TIMEOUT"
	// azcfgKeyVaultName is the environment variable for the Key Vault name.
	azcfgKeyVaultName = "AZCFG_KEYVAULT_NAME"
	// azcfgAppConfigurationName is the environment variable for the App
	// Configuration name.
	azcfgAppConfigurationName = "AZCFG_APPCONFIGURATION_NAME"
	// azcfgTenantID is the environment variable for the tenant ID.
	azcfgTenantID = "AZCFG_TENANT_ID"
	// azcfgClientID is the environment variable for the client ID.
	azcfgClientID = "AZCFG_CLIENT_ID"
	// azcfgClientSecret is the environment variable for the client
	// secret.
	azcfgClientSecret = "AZCFG_CLIENT_SECRET"
	// azcfgClientCertificate is the environment variable for the client
	// certificate.
	azcfgClientCertificate = "AZCFG_CLIENT_CERTIFICATE"
	// azcfgClientCertificatePath is the environment variable for the path
	// to the client certificate.
	azcfgClientCertificatePath = "AZCFG_CLIENT_CERTIFICATE_PATH"
	// azcfgAzureCLICredential is the environment variable for the Azure CLI
	// credential.
	azcfgAzureCLICredential = "AZCFG_AZURE_CLI_CREDENTIAL"
	// azcfgAppConfigurationAccessKeyID is the environment variable for the App
	// Configuration access key ID.
	azcfgAppConfigurationAccessKeyID = "AZCFG_APPCONFIGURATION_ACCESS_KEY_ID"
	// azcfgAppConfigurationAccessKeySecret is the environment variable for the App
	// Configuration access key secret.
	azcfgAppConfigurationAccessKeySecret = "AZCFG_APPCONFIGURATION_ACCESS_KEY_SECRET"
	// azcfgAppConfigurationConnectionString is the environment variable for the App
	// Configuration connection string.
	azcfgAppConfigurationConnectionString = "AZCFG_APPCONFIGURATION_CONNECTION_STRING"
	// azcfgSecretsVersions is the environment variable for the secrets versions.
	azcfgSecretsVersions = "AZCFG_SECRETS_VERSIONS"
	// azcfgSettingsLabel is the environment variable for the settings label.
	azcfgSettingsLabel = "AZCFG_SETTINGS_LABEL"
	// azcfgSettingsLabels is the environment variable for the settings labels.
	azcfgSettingsLabels = "AZCFG_SETTINGS_LABELS"
	// azcfgManagedIdentityIMDSDialTimeout is the environment variable for the dial
	// timeout for testing the IMDS endpoint for managed identities.
	azcfgManagedIdentityIMDSDialTimeout = "AZCFG_MANAGED_IDENTITY_IMDS_DIAL_TIMEOUT"
)

const (
	// defaultTimeout is the default timeout for the clients
	// of the parser.
	defaultTimeout = 30 * time.Second
	// defaultConcurrency is the default concurrency for the
	// clients of the parser.
	defaultConcurrency = 20
	// defaultManagedIdentityIMDSDialTimeout is the default dial timeout
	// for testing the IMDS endpoint for managed identities.
	defaultManagedIdentityIMDSDialTimeout = 3 * time.Second
)

// Options contains options for the Parser.
type Options struct {
	// Credential is the credential to be used with the Client.
	Credential auth.Credential
	// httpClient is the HTTP client for the parser.
	httpClient HTTPClient
	// SecretClient is a client used to retrieve secrets.
	SecretClient SecretClient
	// SettingClient is a client used to retrieve settings.
	SettingClient SettingClient
	// Cloud is the Azure cloud to make requests to. Defaults to AzurePublic.
	Cloud cloud.Cloud
	// KeyVault is the name of the Key Vault containing secrets.
	KeyVault string
	// SecretsVersions is the versions for secrets in Key Vault.
	// They key of the map should be the secret name, and the value
	// should be the version.
	SecretsVersions map[string]string
	// AppConfiguration is the name of the App Configuration containing
	// settings.
	AppConfiguration string
	// SettingsLabel is the label for settings in App Configuration.
	SettingsLabel string
	// SettingsLabels is the labels for settings in an Azure App Configuration.
	// The key of the map should be the setting name, and the value
	// should be the label.
	SettingsLabels map[string]string
	// RetryPolicy is the retry policy for the clients of the parser.
	RetryPolicy RetryPolicy
	// Authentication contains authentication settings for the parser.
	Authentication Authentication
	// Concurrency is the amount of secrets/settings that will be retrieved
	// concurrently. Shared between the secret and the setting client. Defaults to 20.
	Concurrency int
	// Timeout is the total timeout for retrieval of secrets and settings.
	// Shared for all clients. Defaults to 10 seconds.
	Timeout time.Duration
}

// defaultOptions returns the default options for the parser.
func defaultOptions() Options {
	concurrency, err := strconv.Atoi(os.Getenv(azcfgConcurrency))
	if err != nil {
		concurrency = defaultConcurrency
	}

	timeout, err := time.ParseDuration(os.Getenv(azcfgTimeout))
	if err != nil {
		timeout = defaultTimeout
	}

	imdsDialTimeout, err := time.ParseDuration(os.Getenv(azcfgManagedIdentityIMDSDialTimeout))
	if err != nil {
		imdsDialTimeout = defaultManagedIdentityIMDSDialTimeout
	}

	return Options{
		Cloud:            parseCloud(os.Getenv(azcfgCloud)),
		KeyVault:         os.Getenv(azcfgKeyVaultName),
		SecretsVersions:  parseCSVKVP(os.Getenv(azcfgSecretsVersions)),
		AppConfiguration: os.Getenv(azcfgAppConfigurationName),
		SettingsLabel:    os.Getenv(azcfgSettingsLabel),
		SettingsLabels:   parseCSVKVP(os.Getenv(azcfgSettingsLabels)),
		Authentication: Authentication{
			Entra: Entra{
				TenantID:                       os.Getenv(azcfgTenantID),
				ClientID:                       os.Getenv(azcfgClientID),
				ClientSecret:                   os.Getenv(azcfgClientSecret),
				AzureCLICredential:             parseBool(os.Getenv(azcfgAzureCLICredential)),
				certificate:                    os.Getenv(azcfgClientCertificate),
				certificatePath:                os.Getenv(azcfgClientCertificatePath),
				ManagedIdentityIMDSDialTimeout: imdsDialTimeout,
			},
			AppConfigurationAccessKey: AppConfigurationAccessKey{
				ID:     os.Getenv(azcfgAppConfigurationAccessKeyID),
				Secret: os.Getenv(azcfgAppConfigurationAccessKeySecret),
			},
			AppConfigurationConnectionString: os.Getenv(azcfgAppConfigurationConnectionString),
		},
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

// Option is a function that sets Options.
type Option func(o *Options)

// Authentication contains authentication settings for the parser.
type Authentication struct {
	AppConfigurationAccessKey        AppConfigurationAccessKey
	AppConfigurationConnectionString string
	Entra                            Entra
}

// Entra contains authentication settings for Microsoft Entra
// authentication for the parser.
type Entra struct {
	// Assertion is an assertion function for a client assertion credential.
	Assertion func() (string, error)
	// PrivateKey to be used with the certificates for the Service Principal
	// with access to target Key Vault and/or App Configuration.
	PrivateKey *rsa.PrivateKey
	// TenantID of the Service Principal with access to target
	// Key Vault and/or App Configuration.
	TenantID string
	// ClientID of the Service Principal or user assigned managed identity
	// with access to target Key Vault and/or App Configuration.
	ClientID string
	// ClientSecret of the Service Principal with access to target Key Vault
	// and/or App Configuration.
	ClientSecret string
	// certificate is the base64 encoded certificate for the Service Principal.
	certificate string
	// certificatePath is the path to the certificate for the Service Principal.
	certificatePath string
	// Certificates for the Service Principal with access to target Key Vault
	// and/or App Configuration.
	Certificates []*x509.Certificate
	// ManagedIdentity sets the use of a managed identity. To use a user assigned
	// managed identity, use together with ClientID.
	ManagedIdentity bool
	// AzureCLICredential sets the use of Azure CLI credentials.
	AzureCLICredential bool
	// ManagedIdentityIMDSDialTimeout sets the dial timeout for testing the
	// IMDS endpoint for managed identities that makes use of IMDS.
	// Examples are Azure Virtual Machines and Container Instances.
	// Defaults to 3 seconds.
	ManagedIdentityIMDSDialTimeout time.Duration
}

// AppConfigurationAccessKey contains ID and secret for an App Configuration
// access key.
type AppConfigurationAccessKey struct {
	ID     string
	Secret string
}

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
// Shared between the secret and the setting client.
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
		o.Authentication.Entra.TenantID = tenantID
		o.Authentication.Entra.ClientID = clientID
		o.Authentication.Entra.ClientSecret = clientSecret
	}
}

// WithClientCertificateCredential sets the parser to use client credential with
// a certificate (client certificate credential).
func WithClientCertificateCredential(tenantID, clientID string, certificates []*x509.Certificate, key *rsa.PrivateKey) Option {
	return func(o *Options) {
		o.Authentication.Entra.TenantID = tenantID
		o.Authentication.Entra.ClientID = clientID
		o.Authentication.Entra.Certificates = certificates
		o.Authentication.Entra.PrivateKey = key
	}
}

// WithClientAssertionCredential sets the parser to use client credential with an assertion.
// The assertion should be a function that returns a JWT from an identity provider.
func WithClientAssertionCredential(tenantID, clientID string, assertion func() (string, error)) Option {
	return func(o *Options) {
		o.Authentication.Entra.TenantID = tenantID
		o.Authentication.Entra.ClientID = clientID
		o.Authentication.Entra.Assertion = assertion
	}
}

// WithManagedIdentity sets the parser to use a managed identity.
func WithManagedIdentity() Option {
	return func(o *Options) {
		o.Authentication.Entra.ManagedIdentity = true
	}
}

// WithClientID sets the client ID for the parser. Use together
// with option WithManagedIdentity to use a user assigned identity
// with the provided client ID.
func WithClientID(clientID string) Option {
	return func(o *Options) {
		o.Authentication.Entra.ClientID = clientID
	}
}

// WithManagedIdentityIMDSDialTimeout sets the dial timeout for testing the
// IMDS endpoint for managed identities that makes use of IMDS
// (example Azure Virtual Machines and Container Instances).
func WithManagedIdentityIMDSDialTimeout(d time.Duration) Option {
	return func(o *Options) {
		if d > 0 {
			o.Authentication.Entra.ManagedIdentityIMDSDialTimeout = d
		}
	}
}

// WithAzureCLICredential sets the parser to use Azure CLI credential.
func WithAzureCLICredential() Option {
	return func(o *Options) {
		o.Authentication.Entra.AzureCLICredential = true
	}
}

// WithAppConfigurationAccessKey sets the parser to use an App Configuration access key
// for authentication to the App Configuration.
func WithAppConfigurationAccessKey(id, secret string) Option {
	return func(o *Options) {
		o.Authentication.AppConfigurationAccessKey = AppConfigurationAccessKey{
			ID:     id,
			Secret: secret,
		}
	}
}

// WithAppConfigurationConnectionString sets the parser to use an App Configuration connection string
// for authentication to the App Configuration.
func WithAppConfigurationConnectionString(connectionString string) Option {
	return func(o *Options) {
		o.Authentication.AppConfigurationConnectionString = connectionString
	}
}

// WithSecretsVersions sets the versions for secrets in Key Vault.
// They key of the map should be the secret name, and the value
// should be the version.
func WithSecretsVersions(versions map[string]string) Option {
	return func(o *Options) {
		o.SecretsVersions = versions
	}
}

// WithSettingsLabel sets the label for settings in App Configuration.
func WithSettingsLabel(label string) Option {
	return func(o *Options) {
		o.SettingsLabel = label
	}
}

// WithSettingsLabels sets labels for settings in an Azure App Configuration.
// The key of the map should be the setting name, and the value
// should be the label.
func WithSettingsLabels(labels map[string]string) Option {
	return func(o *Options) {
		o.SettingsLabels = labels
	}
}

// WithSecretClient sets the client for secret retrieval.
func WithSecretClient(c SecretClient) Option {
	return func(o *Options) {
		o.SecretClient = c
	}
}

// WithSettingClient sets the client for setting retrieval.
func WithSettingClient(c SettingClient) Option {
	return func(o *Options) {
		o.SettingClient = c
	}
}

// WithCloud sets the Azure cloud to make requests to.
// AzurePublic (Azure), AzureGovernment (Azure Government)
// and AzureChina (Azure China) are supported.
// AzurePublic is used by default.
func WithCloud(c cloud.Cloud) Option {
	return func(o *Options) {
		if !c.Valid() {
			c = cloud.AzurePublic
		}
		o.Cloud = c
	}
}

// WithHTTPClient sets the HTTP client for the parser.
func WithHTTPClient(client HTTPClient) Option {
	return func(o *Options) {
		o.httpClient = client
	}
}

// WithRetryPolicy sets the retry policy for the parser.
func WithRetryPolicy(r RetryPolicy) Option {
	return func(o *Options) {
		o.RetryPolicy = r
	}
}

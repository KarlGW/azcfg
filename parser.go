package azcfg

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/identity"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
)

const (
	// defaultTimeout is the default timeout for the clients
	// of the parser.
	defaultTimeout = time.Second * 10
	// defaultConcurrency is the default concurrency for the
	// clients of the parser.
	defaultConcurrency = 10
)

// secretClient is the interface that wraps around method GetSecrets.
type secretClient interface {
	GetSecrets(names []string, options ...secret.Option) (map[string]secret.Secret, error)
}

// settingClient is the interface that wraps around method GetSettings.
type settingClient interface {
	GetSettings(keys []string, options ...setting.Option) (map[string]setting.Setting, error)
}

// parser contains all the necessary values and settings for calls to Parse.
type parser struct {
	secretClient  secretClient
	settingClient settingClient
	cred          auth.Credential
	label         string
	timeout       time.Duration
	concurrency   int
}

// NewParser creates and returns a *Parser. With no options provided
// it will have default settings for timeout and concurrency.
func NewParser(options ...Option) (*parser, error) {
	p := &parser{
		timeout:     defaultTimeout,
		concurrency: defaultConcurrency,
	}
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}
	if opts.Concurrency > 0 {
		p.concurrency = opts.Concurrency
	}
	if opts.Timeout > 0 {
		p.timeout = opts.Timeout
	}

	vault := setupKeyVault(opts.KeyVault)
	appConfiguration, label := setupAppConfiguration(opts.AppConfiguration, opts.Label)
	if opts.SecretClient == nil && len(vault) > 0 {
		if p.cred == nil {
			var err error
			p.cred, err = setupCredential(opts)
			if err != nil {
				return nil, err
			}
		}
		p.secretClient = secret.NewClient(
			vault,
			p.cred,
			secret.WithTimeout(p.timeout),
			secret.WithConcurrency(p.concurrency),
		)
	} else {
		p.secretClient = opts.SecretClient
	}
	if opts.SettingClient == nil && len(appConfiguration) > 0 {
		if p.cred == nil {
			var err error
			p.cred, err = setupCredential(opts)
			if err != nil {
				return nil, err
			}
		}

		p.label = label
		p.settingClient = setting.NewClient(
			appConfiguration,
			p.cred,
			setting.WithTimeout(p.timeout),
			setting.WithConcurrency(p.concurrency),
		)
	} else {
		p.settingClient = opts.SettingClient
	}

	return p, nil
}

// Parse secrets from an Azure Key Vault into a struct.
func (p *parser) Parse(v any) error {
	return parse(v, p.secretClient, p.settingClient, p.label)
}

// setupCredential configures credential based on the provided
// options.
func setupCredential(options Options) (auth.Credential, error) {
	if options.credFn != nil {
		return options.credFn()
	}

	if options.Credential != nil {
		return options.Credential, nil
	}

	// Function to get settings from either options or environment variables.

	if len(options.TenantID) == 0 && len(options.ClientID) == 0 && len(options.ClientSecret) == 0 && !options.UseManagedIdentity {
		return credentialFromEnvironment()
	} else if len(options.TenantID) > 0 && len(options.ClientID) > 0 && len(options.ClientSecret) > 0 && !options.UseManagedIdentity {
		return credentialFromOptions(options)
	} else if options.UseManagedIdentity {
		return newManagedIdentityCredential(options.ClientID)
	}

	return nil, errors.New("could not determine credentials and authentication method")
}

// credentialFromOptions gets credential details from the provided options.
func credentialFromOptions(options Options) (auth.Credential, error) {
	if len(options.ClientSecret) > 0 {
		return newClientSecretCredential(options.TenantID, options.ClientID, options.ClientSecret)
	}

	if len(options.Certificates) > 0 && options.PrivateKey != nil {
		return newClientCertificateCredential(options.TenantID, options.ClientID, options.Certificates, options.PrivateKey)
	}
	if options.UseManagedIdentity {
		return newManagedIdentityCredential(options.ClientID)
	}
	return nil, nil
}

// credentialFromEnvironment gets credential details from environment variables.
func credentialFromEnvironment() (auth.Credential, error) {
	tenantID, clientID := os.Getenv(azcfgTenantID), os.Getenv(azcfgClientID)

	if clientSecret := os.Getenv(azcfgClientSecret); len(clientSecret) > 0 {
		return newClientSecretCredential(tenantID, clientID, clientSecret)
	}

	certificate, certificatePath := os.Getenv(azcfgCertificate), os.Getenv(azcfgCertificatePath)
	if len(certificate) > 0 || len(certificatePath) > 0 {
		certs, key, err := certificateAndKey(certificate, certificatePath)
		if err != nil {
			return nil, err
		}
		return newClientCertificateCredential(tenantID, clientID, certs, key)
	}
	return newManagedIdentityCredential(clientID)
}

// setupKeyVault configures target Key Vault based on the provided parameters.
func setupKeyVault(vault string) string {
	if len(vault) == 0 {
		return os.Getenv(azcfgKeyVaultName)
	} else {
		return vault
	}
}

// setupAppConfiguration configures target App Configuration based on the provided
// parameters.
func setupAppConfiguration(appConfiguration, label string) (string, string) {
	if len(appConfiguration) == 0 {
		appConfiguration = os.Getenv(azcfgAppConfigurationName)
	}
	if len(label) == 0 {
		label = os.Getenv(azcfgAppConfigurationLabel)
	}
	return appConfiguration, label
}

var newClientSecretCredential = func(tenantID, clientID, clientSecret string) (auth.Credential, error) {
	return identity.NewClientSecretCredential(tenantID, clientID, clientSecret)
}

var newClientCertificateCredential = func(tenantID, clientID string, certificates []*x509.Certificate, key *rsa.PrivateKey) (auth.Credential, error) {
	return identity.NewClientCertificateCredential(tenantID, clientID, certificates, key)
}

var newManagedIdentityCredential = func(clientID string) (auth.Credential, error) {
	return identity.NewManagedIdentityCredential(identity.WithClientID(clientID))
}

// certificateAndKey gets the certificates and keys from the provided certificate or certificate path.
func certificateAndKey(certificate, certificatePath string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	var pem []byte
	var err error
	if len(certificate) > 0 {
		pem, err = base64.StdEncoding.DecodeString(certificate)
	} else if len(certificatePath) > 0 {
		pem, err = os.ReadFile(certificatePath)
	}
	if err != nil {
		return nil, nil, err
	}

	return identity.CertificateAndKeyFomPEM(pem)
}

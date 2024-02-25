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
	if options.Credential != nil {
		return options.Credential, nil
	}

	tenantID := coalesceString(options.TenantID, os.Getenv(azcfgTenantID))
	clientID := coalesceString(options.ClientID, os.Getenv(azcfgClientID))
	if len(tenantID) == 0 || options.UseManagedIdentity {
		return newManagedIdentityCredential(clientID)
	}
	if len(clientID) == 0 {
		return nil, ErrMissingClientID
	}

	clientSecret := coalesceString(options.ClientSecret, os.Getenv(azcfgClientSecret))
	if len(clientSecret) > 0 {
		return newClientSecretCredential(tenantID, clientID, clientSecret)
	}

	var certs []*x509.Certificate
	var key *rsa.PrivateKey
	if len(options.Certificates) > 0 && options.PrivateKey != nil {
		certs, key = options.Certificates, options.PrivateKey
	} else {
		certificate, certificatePath := os.Getenv(azcfgCertificate), os.Getenv(azcfgCertificatePath)
		var err error
		certs, key, err = certificateAndKey(certificate, certificatePath)
		if err != nil {
			return nil, err
		}
	}
	if len(certs) > 0 && key != nil {
		return newClientCertificateCredential(tenantID, clientID, certs, key)
	}

	return nil, errors.New("could not determine credentials and authentication method")
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

// coelesceString returns the first non-empty string (if any).
func coalesceString(x, y string) string {
	if len(x) > 0 {
		return x
	}
	return y
}

// CertificateAndKeyFromPEM extracts the x509 certificates and private key from the given PEM.
var CertificateAndKeyFromPEM = identity.CertificateAndKeyFromPEM

// certificateAndKey gets the certificates and keys from the provided certificate or certificate path.
var certificateAndKey = func(certificate, certificatePath string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
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

	return CertificateAndKeyFromPEM(pem)
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

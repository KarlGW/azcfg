package azcfg

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/identity"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
)

// HTTPClient is an HTTP client with a Do method.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Secret represents a secret as returned from the Key Vault REST API.
type Secret = secret.Secret

// secretClient is the interface that wraps around method GetSecrets.
type secretClient interface {
	GetSecrets(ctx context.Context, names []string, options ...secret.Option) (map[string]Secret, error)
}

// Setting represents a setting as returned from the App Config REST API.
type Setting = setting.Setting

// settingClient is the interface that wraps around method GetSettings.
type settingClient interface {
	GetSettings(ctx context.Context, keys []string, options ...setting.Option) (map[string]Setting, error)
}

// RetryPolicy contains rules for retries.
type RetryPolicy = httpr.RetryPolicy

// parser contains all the necessary values and settings for calls to
// Parse.
type parser struct {
	secretClient  secretClient
	settingClient settingClient
	timeout       time.Duration
}

// NewParser creates and returns a *Parser. This suits situations
// where multiple calls to Parse are needed with the same settings.
func NewParser(options ...Option) (*parser, error) {
	opts := defaultOptions()
	for _, option := range options {
		option(&opts)
	}

	var httpClient HTTPClient
	if opts.httpClient == nil {
		httpClient = httpr.NewClient(
			httpr.WithTimeout(opts.Timeout),
			httpr.WithRetryPolicy(opts.RetryPolicy),
		)
	} else {
		httpClient = opts.httpClient
	}

	var cred auth.Credential
	if opts.Credential != nil {
		cred = opts.Credential
	}

	var secretClient secretClient
	if opts.SecretClient == nil && len(opts.KeyVault) > 0 {
		var err error
		if cred == nil {
			cred, err = setupCredential(opts.Cloud, opts.Authentication.Entra)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrCredential, err.Error())
			}
		}

		concurrency := opts.Concurrency
		if len(opts.AppConfiguration) > 0 || len(opts.Authentication.AppConfigurationConnectionString) > 0 {
			concurrency /= 2
		}

		secretClient, err = secret.NewClient(
			opts.KeyVault,
			cred,
			secret.WithHTTPClient(httpClient),
			secret.WithConcurrency(concurrency),
			secret.WithCloud(opts.Cloud),
			secret.WithClientVersions(opts.SecretsVersions),
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrSecretClient, err.Error())
		}
	} else {
		secretClient = opts.SecretClient
	}

	var settingClient settingClient
	if opts.SettingClient == nil && len(opts.AppConfiguration) > 0 || len(opts.Authentication.AppConfigurationConnectionString) > 0 {
		var err error
		if opts.Authentication.AppConfigurationAccessKey == (AppConfigurationAccessKey{}) && len(opts.Authentication.AppConfigurationConnectionString) == 0 {
			if cred == nil {
				cred, err = setupCredential(opts.Cloud, opts.Authentication.Entra)
				if err != nil {
					return nil, fmt.Errorf("%w: %s", ErrCredential, err.Error())
				}
			}
		}

		concurrency := opts.Concurrency
		if len(opts.KeyVault) > 0 {
			concurrency /= 2
		}

		options := []setting.ClientOption{
			setting.WithHTTPClient(httpClient),
			setting.WithConcurrency(concurrency),
			setting.WithCloud(opts.Cloud),
			setting.WithClientLabel(opts.SettingsLabel),
			setting.WithClientLabels(opts.SettingsLabels),
		}

		settingClient, err = newSettingClient(
			settings{
				credential:       cred,
				appConfiguration: opts.AppConfiguration,
				accessKey:        opts.Authentication.AppConfigurationAccessKey,
				connectionString: opts.Authentication.AppConfigurationConnectionString,
			},
			options...,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrSettingClient, err.Error())
		}
	} else {
		settingClient = opts.SettingClient
	}

	return &parser{
		secretClient:  secretClient,
		settingClient: settingClient,
		timeout:       opts.Timeout,
	}, nil
}

// Parse secrets from an Azure Key Vault and settings from an
// Azure App Configuration into the provided struct.
func (p *parser) Parse(ctx context.Context, v any) error {
	return parse(ctx, v, parseOptions{
		secretClient:  p.secretClient,
		settingClient: p.settingClient,
	})
}

// setupCredential configures credential based on the provided
// options.
func setupCredential(cloud cloud.Cloud, entra Entra) (auth.Credential, error) {
	if entra.AzureCLICredential {
		return identity.NewAzureCLICredential(identity.WithCloud(cloud))
	}

	if len(entra.TenantID) == 0 || entra.ManagedIdentity {
		cred, err := identity.NewManagedIdentityCredential(
			identity.WithClientID(entra.ClientID),
			identity.WithCloud(cloud),
			identity.WithIMDSDialTimeout(entra.ManagedIdentityIMDSDialTimeout),
		)
		if err != nil && !errors.Is(err, identity.ErrIMDSEndpointUnavailable) {
			return nil, err
		}
		if cred != nil {
			return cred, nil
		}
	}

	if len(entra.ClientSecret) > 0 {
		return identity.NewClientSecretCredential(entra.TenantID, entra.ClientID, entra.ClientSecret, identity.WithCloud(cloud))
	}

	var certs []*x509.Certificate
	var key *rsa.PrivateKey
	if len(entra.Certificates) > 0 && entra.PrivateKey != nil {
		certs, key = entra.Certificates, entra.PrivateKey
	} else if len(entra.certificate) > 0 || len(entra.certificatePath) > 0 {
		var err error
		certs, key, err = certificateAndKey(entra.certificate, entra.certificatePath)
		if err != nil {
			return nil, err
		}
	}
	if len(certs) > 0 && key != nil {
		return identity.NewClientCertificateCredential(entra.TenantID, entra.ClientID, certs, key, identity.WithCloud(cloud))
	}

	if entra.Assertion != nil {
		return identity.NewClientAssertionCredential(entra.TenantID, entra.ClientID, entra.Assertion, identity.WithCloud(cloud))
	}

	return nil, errors.New("could not determine and create entra credential")
}

// settings contains the necessary values for setting client creation.
type settings struct {
	credential       auth.Credential
	accessKey        AppConfigurationAccessKey
	appConfiguration string
	connectionString string
}

// newSettingClient creates a new setting client based on the provided settings.
func newSettingClient(settings settings, options ...setting.ClientOption) (settingClient, error) {
	if len(settings.appConfiguration) > 0 && settings.credential != nil {
		return setting.NewClient(
			settings.appConfiguration,
			settings.credential,
			options...,
		)
	}
	if len(settings.connectionString) > 0 {
		return setting.NewClientWithConnectionString(
			settings.connectionString,
			options...,
		)
	}

	if len(settings.appConfiguration) > 0 && len(settings.accessKey.ID) > 0 && len(settings.accessKey.Secret) > 0 {
		return setting.NewClientWithAccessKey(
			settings.appConfiguration,
			setting.AccessKey{
				ID:     settings.accessKey.ID,
				Secret: settings.accessKey.Secret,
			},
			options...,
		)
	}

	return nil, errors.New("could not determine and create app configuration credential")
}

// certificatesAndKeyFromPEM extracts the x509 certificates and private key from the given PEM.
var certificatesAndKeyFromPEM = identity.CertificatesAndKeyFromPEM

// certificateAndKey gets the certificates and keys from the provided certificate or certificate path.
func certificateAndKey(certificate, certificatePath string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	var pem []byte
	var err error
	if len(certificate) > 0 {
		pem, err = base64.StdEncoding.DecodeString(certificate)
	} else if len(certificatePath) > 0 {
		pem, err = os.ReadFile(certificatePath)
	} else {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	return certificatesAndKeyFromPEM(pem)
}

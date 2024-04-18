package azcfg

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/identity"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
)

// secretClient is the interface that wraps around method GetSecrets.
type secretClient interface {
	GetSecrets(ctx context.Context, names []string, options ...secret.Option) (map[string]secret.Secret, error)
}

// settingClient is the interface that wraps around method GetSettings.
type settingClient interface {
	GetSettings(ctx context.Context, keys []string, options ...setting.Option) (map[string]setting.Setting, error)
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

// NewParser creates and returns a *Parser. With no options provided
// it will have default settings for timeout and concurrency.
func NewParser(options ...Option) (*parser, error) {
	opts := defaultOptions()
	for _, option := range options {
		option(&opts)
	}

	var cred auth.Credential
	if opts.Credential != nil {
		cred = opts.Credential
	}

	var secretClient secretClient
	if opts.SecretClient == nil && len(opts.KeyVault) > 0 {
		if cred == nil {
			var err error
			cred, err = setupCredential(opts.Cloud, opts.Authentication.Entra)
			if err != nil {
				return nil, err
			}
		}

		concurrency := opts.Concurrency
		if len(opts.AppConfiguration) > 0 || len(opts.Authentication.AppConfigurationConnectionString) > 0 {
			concurrency /= 2
		}

		secretClient = secret.NewClient(
			opts.KeyVault,
			cred,
			secret.WithTimeout(opts.Timeout),
			secret.WithConcurrency(concurrency),
			secret.WithRetryPolicy(opts.RetryPolicy),
			secret.WithCloud(opts.Cloud),
		)
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
					return nil, err
				}
			}
		}

		concurrency := opts.Concurrency
		if len(opts.KeyVault) > 0 {
			concurrency /= 2
		}

		options := []setting.ClientOption{
			setting.WithTimeout(opts.Timeout),
			setting.WithConcurrency(concurrency),
			setting.WithRetryPolicy(opts.RetryPolicy),
			setting.WithCloud(opts.Cloud),
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
			return nil, err
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

// Parse secrets from an Azure Key Vault into a struct.
//
// The only valid option is context, the other options on the
// parser remain unaffected.
func (p *parser) Parse(v any, options ...Option) error {
	opts := Options{}
	for _, option := range options {
		option(&opts)
	}

	var ctx context.Context
	if opts.Context == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), p.timeout)
		defer cancel()
	} else {
		ctx = opts.Context
	}

	return parse(ctx, v, parseOptions{
		secretClient:  p.secretClient,
		settingClient: p.settingClient,
		label:         coalesceString(opts.Label, os.Getenv(azcfgAppConfigurationLabel)),
		labels:        coalesceMap(opts.Labels, parseLabels(os.Getenv(azcfgAppConfigurationLabels))),
	})
}

// setupCredential configures credential based on the provided
// options.
func setupCredential(cloud cloud.Cloud, entra Entra) (auth.Credential, error) {
	if entra.AzureCLICredential {
		return newAzureCLICredential(identity.WithCloud(cloud))
	}

	if len(entra.TenantID) == 0 || entra.ManagedIdentity {
		if entra.ManagedIdentityIMDSDialTimeout == 0 {
			entra.ManagedIdentityIMDSDialTimeout = time.Second * 3
		}

		cred, err := newManagedIdentityCredential(
			entra.ClientID,
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
		return newClientSecretCredential(entra.TenantID, entra.ClientID, entra.ClientSecret, identity.WithCloud(cloud))
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
		return newClientCertificateCredential(entra.TenantID, entra.ClientID, certs, key, identity.WithCloud(cloud))
	}

	if entra.Assertion != nil {
		return newClientAssertionCredential(entra.TenantID, entra.ClientID, entra.Assertion, identity.WithCloud(cloud))
	}

	return nil, fmt.Errorf("%w: could not determine and create Entra credential", ErrInvalidCredential)
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

	return nil, fmt.Errorf("%w: could not determine and create app configuration credential", ErrInvalidCredential)
}

// certificatesAndKeyFromPEM extracts the x509 certificates and private key from the given PEM.
var certificatesAndKeyFromPEM = identity.CertificatesAndKeyFromPEM

// certificateAndKey gets the certificates and keys from the provided certificate or certificate path.
var certificateAndKey = func(certificate, certificatePath string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
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

var newClientSecretCredential = func(tenantID, clientID, clientSecret string, options ...identity.CredentialOption) (*identity.ClientCredential, error) {
	return identity.NewClientSecretCredential(tenantID, clientID, clientSecret, options...)
}

var newClientCertificateCredential = func(tenantID, clientID string, certificates []*x509.Certificate, key *rsa.PrivateKey, options ...identity.CredentialOption) (*identity.ClientCredential, error) {
	return identity.NewClientCertificateCredential(tenantID, clientID, certificates, key, options...)
}

var newClientAssertionCredential = func(tenantID, clientID string, assertion func() (string, error), options ...identity.CredentialOption) (*identity.ClientCredential, error) {
	return identity.NewClientAssertionCredential(tenantID, clientID, assertion, options...)
}

var newManagedIdentityCredential = func(clientID string, options ...identity.CredentialOption) (*identity.ManagedIdentityCredential, error) {
	return identity.NewManagedIdentityCredential(append(options, identity.WithClientID(clientID))...)
}

var newAzureCLICredential = func(options ...identity.CredentialOption) (*identity.AzureCLICredential, error) {
	return identity.NewAzureCLICredential(options...)
}

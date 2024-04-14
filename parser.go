package azcfg

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
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

const (
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
	// azcfgKeyVaultName is the environment variable for the Key Vault name.
	azcfgKeyVaultName = "AZCFG_KEYVAULT_NAME"
	// azcfgAppConfigurationName is the environment variable for the App
	// Configuration name.
	azcfgAppConfigurationName = "AZCFG_APPCONFIGURATION_NAME"
	// azcfgAppConfigurationLabel is the environment variable for the App
	// Configuration label.
	azcfgAppConfigurationLabel = "AZCFG_APPCONFIGURATION_LABEL"
	// azcfgAppConfigurationLabels is the environment variable for the App
	// Configuration labels.
	azcfgAppConfigurationLabels = "AZCFG_APPCONFIGURATION_LABELS"
	// azcfgAzureCLICredential is the environment variable for the Azure CLI
	// credential.
	azcfgAzureCLICredential = "AZCFG_AZURE_CLI_CREDENTIAL"
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
	cred          auth.Credential
	label         string
	labels        map[string]string
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
	opts := Options{
		Cloud: cloud.AzurePublic,
	}
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
	appConfiguration, label, labels := setupAppConfiguration(opts.AppConfiguration, opts.Label, opts.Labels)
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
			secret.WithRetryPolicy(opts.RetryPolicy),
			secret.WithCloud(opts.Cloud),
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
		p.labels = labels
		p.settingClient = setting.NewClient(
			appConfiguration,
			p.cred,
			setting.WithTimeout(p.timeout),
			setting.WithConcurrency(p.concurrency),
			setting.WithRetryPolicy(opts.RetryPolicy),
			setting.WithCloud(opts.Cloud),
		)
	} else {
		p.settingClient = opts.SettingClient
	}

	return p, nil
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
		label:         p.label,
		labels:        p.labels,
	})
}

// setupCredential configures credential based on the provided
// options.
func setupCredential(options Options) (auth.Credential, error) {
	if options.Credential != nil {
		return options.Credential, nil
	}

	if coalesceBool(options.AzureCLICredential, parseBool(os.Getenv(azcfgAzureCLICredential))) {
		return newAzureCLICredential(identity.WithCloud(options.Cloud))
	}

	tenantID := coalesceString(options.TenantID, os.Getenv(azcfgTenantID))
	clientID := coalesceString(options.ClientID, os.Getenv(azcfgClientID))
	if len(tenantID) == 0 || options.ManagedIdentity {
		if options.ManagedIdentityIMDSDialTimeout == 0 {
			options.ManagedIdentityIMDSDialTimeout = time.Second * 3
		}
		cred, err := newManagedIdentityCredential(
			clientID,
			identity.WithCloud(options.Cloud),
			identity.WithIMDSDialTimeout(options.ManagedIdentityIMDSDialTimeout),
		)
		if err != nil && !errors.Is(err, identity.ErrIMDSEndpointUnavailable) {
			return nil, err
		}
		if cred != nil {
			return cred, nil
		}
	}

	clientSecret := coalesceString(options.ClientSecret, os.Getenv(azcfgClientSecret))
	if len(clientSecret) > 0 {
		return newClientSecretCredential(tenantID, clientID, clientSecret, identity.WithCloud(options.Cloud))
	}

	var certs []*x509.Certificate
	var key *rsa.PrivateKey
	if len(options.Certificates) > 0 && options.PrivateKey != nil {
		certs, key = options.Certificates, options.PrivateKey
	} else {
		certificate, certificatePath := os.Getenv(azcfgClientCertificate), os.Getenv(azcfgClientCertificatePath)
		var err error
		certs, key, err = certificateAndKey(certificate, certificatePath)
		if err != nil {
			return nil, err
		}
	}

	if options.Assertion != nil {
		return newClientAssertionCredential(tenantID, clientID, options.Assertion, identity.WithCloud(options.Cloud))
	}

	if len(certs) > 0 && key != nil {
		return newClientCertificateCredential(tenantID, clientID, certs, key, identity.WithCloud(options.Cloud))
	}

	return nil, fmt.Errorf("%w: could not determine credential", ErrInvalidCredential)
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
func setupAppConfiguration(appConfiguration, label string, labels map[string]string) (string, string, map[string]string) {
	if len(appConfiguration) == 0 {
		appConfiguration = os.Getenv(azcfgAppConfigurationName)
	}
	if len(label) == 0 {
		label = os.Getenv(azcfgAppConfigurationLabel)
	}
	if len(labels) == 0 {
		labels = parseLabels(os.Getenv(azcfgAppConfigurationLabels))
	}

	return appConfiguration, label, labels
}

// coelesceString returns the first non-empty string (if any).
func coalesceString(x, y string) string {
	if len(x) > 0 {
		return x
	}
	return y
}

// parseBool returns the boolean represented by the string.
// If the string cannot be parsed, it returns false.
func parseBool(s string) bool {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false
	}
	return b
}

// coalesceBool returns the first non-false boolean (if any).
func coalesceBool(x, y bool) bool {
	if x {
		return x
	}
	return y
}

// parseLabels from the provided string. Format: setting1=label1,setting2=label2.
func parseLabels(labels string) map[string]string {
	if len(labels) == 0 {
		return nil
	}

	re := regexp.MustCompile(`\s+`)
	parts := strings.Split(re.ReplaceAllString(labels, ""), ",")
	m := make(map[string]string)
	for i := range parts {
		p := strings.Split(parts[i], "=")
		m[p[0]] = p[1]
	}
	return m
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

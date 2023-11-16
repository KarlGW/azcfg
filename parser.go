package azcfg

import (
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

// secretClient is the interface that wraps around method GetSecrets
// and KeyVault.
type secretClient interface {
	GetSecrets(names []string, options ...secret.Option) (map[string]secret.Secret, error)
	KeyVault() string
}

// settingClient is the interface that wraps around method GetSettings
// and AppConfiguration.
type settingClient interface {
	GetSettings(keys []string, options ...setting.Option) (map[string]setting.Setting, error)
	AppConfiguration() string
}

// parser contains all the necessary values and settings for calls to Parse.
type parser struct {
	secretClient  secretClient
	settingClient settingClient
	cred          auth.Credential
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

	if opts.SecretClient == nil {
		if p.cred == nil {
			var err error
			p.cred, err = setupCredential(opts)
			if err != nil {
				return nil, err
			}
		}
		p.secretClient = secret.NewClient(
			setupKeyVault(opts.KeyVault),
			p.cred,
			secret.WithTimeout(p.timeout),
			secret.WithConcurrency(p.concurrency),
		)
	} else {
		p.secretClient = opts.SecretClient
	}
	if opts.SettingClient == nil {
		if p.cred == nil {
			var err error
			p.cred, err = setupCredential(opts)
			if err != nil {
				return nil, err
			}
		}

		appConfiguration, label := setupAppConfiguration(opts.AppConfiguration, opts.Label)
		p.settingClient = setting.NewClient(
			appConfiguration,
			p.cred,
			setting.WithLabel(label),
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
	return parse(v, p.secretClient, p.settingClient)
}

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

// setupKeyVault configures target Key Vault based on the provided parameters.
func setupKeyVault(vault string) string {
	if len(vault) == 0 {
		return os.Getenv("AZCFG_KEYVAULT_NAME")
	} else {
		return vault
	}
}

// setupAppConfiguration configures target App Configuration based on the provided
// parameters.
func setupAppConfiguration(appConfiguration, label string) (string, string) {
	if len(appConfiguration) == 0 {
		appConfiguration = os.Getenv("AZCFG_APP_CONFIGURATION_NAME")
	}
	if len(label) == 0 {
		label = os.Getenv("AZCFG_APP_CONFIGURATION_LABEL")
	}
	return appConfiguration, label
}

var newClientCredential = func(tenantID, clientID, clientSecret string) (auth.Credential, error) {
	return identity.NewClientCredential(tenantID, clientID, identity.WithSecret(clientSecret))
}

var newManagedIdentityCredential = func(clientID string) (auth.Credential, error) {
	return identity.NewManagedIdentityCredential(identity.WithClientID(clientID))
}

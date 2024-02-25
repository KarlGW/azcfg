package azcfg

import (
	"errors"
	"os"
	"time"

	"github.com/KarlGW/azcfg/auth"
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

	credFn := credentialFuncFromOptions(options)
	if credFn != nil {
		return credFn()
	}

	var err error
	credFn, err = credentialFuncFromEnvironment()
	if err != nil {
		return nil, err
	}
	if credFn != nil {
		return credFn()
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

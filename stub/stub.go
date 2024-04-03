package stub

import (
	"context"

	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
)

// SecretClient satisfies the secretClient interface in package azcfg. Purpose is
// to be used as a stub for secret retrieval.
type SecretClient struct {
	secrets map[string]secret.Secret
	err     error
}

// NewSecretClient creates a new SecretClient. Argument the map[string]string secrets
// should be key-value pairs of secret names and values. Argument
// error is to set if method calls should return an error.
func NewSecretClient(secrets map[string]string, err error) SecretClient {
	s := make(map[string]secret.Secret, len(secrets))
	for k, v := range secrets {
		s[k] = secret.Secret{
			Value: v,
		}
	}
	return SecretClient{
		secrets: s,
		err:     err,
	}
}

// Get secrets set to the stub client.
func (c SecretClient) GetSecrets(ctx context.Context, names []string, options ...secret.Option) (map[string]secret.Secret, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.secrets, nil
}

// SettingClient satisfies the settingClient interface in package azcfg. Purpose is
// to be used as a stub for setting retrieval.
type SettingClient struct {
	settings map[string]setting.Setting
	err      error
}

// NewSettingClient creates a new SettingClient. Argument the map[string]string settings
// should be key-value pairs of setting keys and values. Argument
// error is to set if method calls should return an error.
func NewSettingClient(settings map[string]string, err error) SettingClient {
	s := make(map[string]setting.Setting, len(settings))
	for k, v := range settings {
		s[k] = setting.Setting{
			Value: v,
		}
	}
	return SettingClient{
		settings: s,
		err:      err,
	}
}

// Get settings set to the stub client.
func (c SettingClient) GetSettings(ctx context.Context, keys []string, options ...setting.Option) (map[string]setting.Setting, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.settings, nil
}

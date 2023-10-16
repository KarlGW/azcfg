package stub

import "github.com/KarlGW/azcfg/internal/secret"

// SecretClient satisfies the secretClient interface in package azcfg. Purpose is
// to be used as a stub for secret retrieval.
type SecretClient struct {
	secrets map[string]secret.Secret
	err     error
}

// NewSecretClient creates a new SecretClient. Argument the map[string] secrets
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
func (c SecretClient) Get(names ...string) (map[string]secret.Secret, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.secrets, nil
}

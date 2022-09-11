package keyvault

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/google/go-cmp/cmp"
)

func TestGetSecrets(t *testing.T) {
	var tests = []struct {
		name    string
		input   []string
		want    map[string]string
		wantErr error
	}{
		{
			name:  "success",
			input: []string{"secret-a", "secret-b", "secret-c"},
			want: map[string]string{
				"secret-a": "a",
				"secret-b": "b",
				"secret-c": "c",
			},
			wantErr: nil,
		},
		{
			name:    "failure",
			input:   []string{"no-secret-a"},
			want:    map[string]string{},
			wantErr: errors.New("no secret"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newMockClient()
			got, err := client.GetSecrets(test.input)

			if test.wantErr == nil && err != nil {
				t.Errorf("should not return error")
			}

			if !cmp.Equal(test.want, got) {
				t.Log(cmp.Diff(test.want, got))
				t.Errorf("results differ")
			}

			if test.wantErr != nil && err == nil {
				t.Errorf("should return error")
			}
		})
	}
}

type mockKeyVaultClient struct {
	secrets map[string]string
}

func newMockClient() *Client {
	return &Client{
		client:      newMockKeyVaultClient(),
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
}

func newMockKeyVaultClient() *mockKeyVaultClient {
	secrets := map[string]string{
		"secret-a": "a",
		"secret-b": "b",
		"secret-c": "c",
	}

	return &mockKeyVaultClient{
		secrets: secrets,
	}
}

func (c mockKeyVaultClient) GetSecret(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	var value string
	if v, ok := c.secrets[name]; !ok {
		return azsecrets.GetSecretResponse{}, errors.New("no secret")
	} else {
		value = v
	}
	secretResponse := azsecrets.GetSecretResponse{
		SecretBundle: azsecrets.SecretBundle{
			Value: &value,
		},
	}

	return secretResponse, nil
}

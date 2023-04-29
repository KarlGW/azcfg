package keyvault

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestGetSecrets(t *testing.T) {
	var tests = []struct {
		name      string
		input     []string
		errorType errorType
		want      map[string]string
		wantErr   error
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
			name:      "secret not found",
			input:     []string{"no-secret-a"},
			errorType: errorType(2),
			want: map[string]string{
				"no-secret-a": "",
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newMockClient(test.errorType)
			got, err := client.GetSecrets(test.input)

			if test.wantErr == nil && err != nil {
				t.Errorf("should not return error")
			}

			if !cmp.Equal(test.want, got) {
				t.Log(cmp.Diff(test.want, got))
				t.Errorf("results differ")
			}

			if test.wantErr != nil && err != nil {
				if !cmp.Equal(test.wantErr.Error(), err.Error(), cmpopts.EquateErrors()) {
					t.Log(cmp.Diff(test.wantErr.Error(), err.Error(), cmpopts.EquateErrors()))
					t.Errorf("results differ")
				}
			}
		})
	}
}

type errorType int

var (
	errorTypeOtherError    errorType = 1
	errorTypeResponseError errorType = 2
)

type mockKeyVaultClient struct {
	errorType errorType
	secrets   map[string]string
}

func newMockClient(et errorType) *Client {
	return &Client{
		client:      newMockKeyVaultClient(et),
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
}

func newMockKeyVaultClient(et errorType) *mockKeyVaultClient {
	secrets := map[string]string{
		"secret-a": "a",
		"secret-b": "b",
		"secret-c": "c",
	}

	return &mockKeyVaultClient{
		secrets:   secrets,
		errorType: et,
	}
}

func (c mockKeyVaultClient) GetSecret(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	var value string
	if v, ok := c.secrets[name]; !ok {
		if c.errorType == errorTypeResponseError {
			rerr := &azcore.ResponseError{
				StatusCode: http.StatusNotFound,
				RawResponse: &http.Response{
					Body: io.NopCloser(bytes.NewBuffer([]byte(`{"error":{"code":"SecretNotFound","message":"secret not found"}}`))),
				},
			}
			return azsecrets.GetSecretResponse{}, rerr
		} else if c.errorType == errorTypeOtherError {
			return azsecrets.GetSecretResponse{}, errors.New("secret not found")
		}

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

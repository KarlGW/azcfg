package setting

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	errRequest = errors.New("request error")
	errServer  = errors.New("internal server error")
)

func TestClient_GetSettings(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			keys    []string
			options []Option
			bodies  map[string][]byte
			secrets map[string]secret.Secret
			err     error
		}
		want    map[string]Setting
		wantErr error
	}{
		{
			name: "get settings",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				secrets map[string]secret.Secret
				err     error
			}{
				keys: []string{"setting-a", "setting-b", "setting-c"},
				bodies: map[string][]byte{
					"setting-a": []byte(`{"value":"a"}`),
					"setting-b": []byte(`{"value":"b"}`),
					"setting-c": []byte(`{"value":"c"}`),
				},
			},
			want: map[string]Setting{
				"setting-a": {Value: "a"},
				"setting-b": {Value: "b"},
				"setting-c": {Value: "c"},
			},
			wantErr: nil,
		},
		{
			name: "get settings with key vault references",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				secrets map[string]secret.Secret
				err     error
			}{
				keys: []string{"setting-a", "setting-b", "setting-c"},
				bodies: map[string][]byte{
					"setting-a": []byte(`{"content_type":"` + keyVaultReferenceContentType + `","value":"{\"uri\":\"https://testvault.vault.azure.net/secrets/secret-1\"}"}`),
					"setting-b": []byte(`{"value":"b"}`),
					"setting-c": []byte(`{"value":"c"}`),
				},
				secrets: map[string]secret.Secret{
					"secret-1": {Value: "1"},
				},
			},
			want: map[string]Setting{
				"setting-a": {ContentType: keyVaultReferenceContentType, Value: "1"},
				"setting-b": {Value: "b"},
				"setting-c": {Value: "c"},
			},
			wantErr: nil,
		},
		{
			name: "setting not found",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				secrets map[string]secret.Secret
				err     error
			}{
				keys: []string{"setting-a", "setting-b", "setting-c"},
				bodies: map[string][]byte{
					"setting-a": []byte(`{"value":"a"}`),
					"setting-c": []byte(`{"value":"c"}`),
				},
			},
			want: map[string]Setting{
				"setting-a": {Value: "a"},
				"setting-b": {Value: ""},
				"setting-c": {Value: "c"},
			},
			wantErr: nil,
		},
		{
			name: "setting not found (key vault reference)",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				secrets map[string]secret.Secret
				err     error
			}{
				keys: []string{"setting-a", "setting-b", "setting-c"},
				bodies: map[string][]byte{
					"setting-a": []byte(`{"content_type":"` + keyVaultReferenceContentType + `","value":"{\"uri\":\"https://testvault.vault.azure.net/secrets/secret-1\"}"}`),
					"setting-b": []byte(`{"value":"b"}`),
					"setting-c": []byte(`{"value":"c"}`),
				},
			},
			want: map[string]Setting{
				"setting-a": {ContentType: keyVaultReferenceContentType, Value: ""},
				"setting-b": {Value: "b"},
				"setting-c": {Value: "c"},
			},
			wantErr: nil,
		},
		{
			name: "server error",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				secrets map[string]secret.Secret
				err     error
			}{
				keys: []string{"setting-a"},
				err:  errServer,
			},
			want: nil,
			wantErr: settingError{
				Detail:     "bad request",
				Status:     http.StatusBadRequest,
				StatusCode: http.StatusBadRequest,
			},
		},
		{
			name: "request error",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				secrets map[string]secret.Secret
				err     error
			}{
				keys: []string{"setting-a"},
				err:  errRequest,
			},
			want:    nil,
			wantErr: errRequest,
		},
		{
			name: "get secret error",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				secrets map[string]secret.Secret
				err     error
			}{
				keys: []string{"setting-a", "setting-b", "setting-c"},
				bodies: map[string][]byte{
					"setting-a": []byte(`{"content_type":"` + keyVaultReferenceContentType + `","value":"{\"uri\":\"https://testvault.vault.azure.net/secrets/secret-1\"}"}`),
				},
				secrets: map[string]secret.Secret{
					"secret-1": {Value: "1"},
				},
				err: errGetSecret,
			},
			wantErr: errGetSecret,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewClient("config", mockCredential{}, func(c *Client) {
				c.c = mockHttpClient{
					bodies: test.input.bodies,
					err:    test.input.err,
				}
				c.sc = &mockSecretClient{
					secrets: test.input.secrets,
					err:     test.input.err,
				}
				c.timeout = time.Millisecond * 10
			})

			got, gotErr := client.GetSettings(test.input.keys, test.input.options...)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("GetSettings() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("GetSettings() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestClient_getSecret(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			secretClient secretClient
			secrets      map[string]secret.Secret
			uri          string
			err          error
		}
		want    secret.Secret
		wantErr error
	}{
		{
			name: "get secret from uri",
			input: struct {
				secretClient secretClient
				secrets      map[string]secret.Secret
				uri          string
				err          error
			}{
				secrets: map[string]secret.Secret{
					"secretname": {Value: "secret"},
				},
				uri: "https://testvault.vault.azure.net/secrets/secretname",
			},
			want: secret.Secret{Value: "secret"},
		},
		{
			name: "get secret from uri (existing client)",
			input: struct {
				secretClient secretClient
				secrets      map[string]secret.Secret
				uri          string
				err          error
			}{
				secretClient: func() *mockSecretClient {
					return &mockSecretClient{
						secrets: map[string]secret.Secret{
							"secretname": {Value: "secret"},
						},
					}
				}(),
				uri: "https://testvault.vault.azure.net/secrets/secretname",
			},
			want: secret.Secret{Value: "secret"},
		},
		{
			name: "get secret - not found",
			input: struct {
				secretClient secretClient
				secrets      map[string]secret.Secret
				uri          string
				err          error
			}{
				secrets: map[string]secret.Secret{},
				uri:     "https://testvault.vault.azure.net/secrets/secretname",
			},
			want: secret.Secret{Value: ""},
		},
		{
			name: "get secret from uri - error",
			input: struct {
				secretClient secretClient
				secrets      map[string]secret.Secret
				uri          string
				err          error
			}{
				secrets: map[string]secret.Secret{
					"secretname": {Value: "secret"},
				},
				uri: "https://testvault.vault.azure.net/secrets/secretname",
				err: errGetSecret,
			},
			wantErr: errGetSecret,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newSecretClient = func(_ string, _ auth.Credential, _ ...secret.ClientOption) secretClient {
				return &mockSecretClient{
					secrets: test.input.secrets,
					err:     test.input.err,
				}
			}

			client := NewClient("config", mockCredential{}, func(c *Client) {
				c.c = mockHttpClient{}
				c.sc = test.input.secretClient
				c.timeout = time.Millisecond * 10
			})

			got, gotErr := client.getSecret(context.Background(), test.input.uri)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("getSecret() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("getSecret() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestClient_vaultAndSecret(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  struct {
			vault, secret string
		}
	}{
		{
			name:  "vault and secret",
			input: "https://testvault.vault.azure.net/secrets/secretname",
			want: struct {
				vault, secret string
			}{
				vault:  "testvault",
				secret: "secretname",
			},
		},
		{
			name:  "vault and secret (with version)",
			input: "https://testvault.vault.azure.net/secrets/secretname/12345",
			want: struct {
				vault, secret string
			}{
				vault:  "testvault",
				secret: "secretname/12345",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotVault, gotSecret := vaultAndSecret(test.input)

			if test.want.vault != gotVault {
				t.Errorf("vaultAndSecret() = unexpected vault, want: %s, got: %s\n", test.want.vault, gotVault)
			}

			if test.want.secret != gotSecret {
				t.Errorf("vaultAndSecret() = unexpected secret, want: %s, got: %s\n", test.want.secret, gotSecret)
			}
		})
	}
}

type mockCredential struct {
	err error
}

func (c mockCredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	if c.err != nil && !errors.Is(c.err, errGetSecret) {
		return auth.Token{}, c.err
	}
	return auth.Token{AccessToken: "ey1235"}, nil
}

type mockHttpClient struct {
	err    error
	bodies map[string][]byte
}

func (c mockHttpClient) Do(req *http.Request) (*http.Response, error) {
	if c.err != nil && !errors.Is(c.err, errGetSecret) {
		if errors.Is(c.err, errServer) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"detail":"bad request","status":400}`))),
			}, nil
		}
		return nil, c.err
	}

	name := path.Base(req.URL.Path)
	b, ok := c.bodies[name]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"error":{}}`))),
		}, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(b)),
	}, nil
}

type mockSecretClient struct {
	err     error
	secrets map[string]secret.Secret
	vault   string
}

func (c mockSecretClient) Vault() string {
	return c.vault
}

func (c *mockSecretClient) SetVault(vault string) {
	c.vault = vault
}

func (c mockSecretClient) Get(ctx context.Context, name string, options ...secret.Option) (secret.Secret, error) {
	if c.err != nil && errors.Is(c.err, errGetSecret) {
		return secret.Secret{}, c.err
	}
	s, ok := c.secrets[name]
	if !ok {
		return secret.Secret{}, nil
	}
	return s, nil
}

var (
	errGetSecret = errors.New("error getting secret")
)

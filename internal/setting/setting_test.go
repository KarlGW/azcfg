package setting

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewClient(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			appConfiguration string
			cred             auth.Credential
			options          []ClientOption
		}
		want    *Client
		wantErr error
	}{
		{
			name: "defaults",
			input: struct {
				appConfiguration string
				cred             auth.Credential
				options          []ClientOption
			}{
				appConfiguration: "config",
				cred:             &mockCredential{},
			},
			want: &Client{
				cred:        &mockCredential{},
				cloud:       cloud.AzurePublic,
				scope:       "https://azconfig.io/.default",
				baseURL:     "https://config.azconfig.io/kv",
				userAgent:   "azcfg/" + version.Version(),
				concurrency: defaultConcurrency,
				timeout:     defaultTimeout,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewClient(test.input.appConfiguration, test.input.cred, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Client{}, mockCredential{}), cmpopts.IgnoreFields(Client{}, "c", "mu")); diff != "" {
				t.Errorf("NewClient() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewClient() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestNewClientWithAccessKey(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			appConfiguration string
			key              AccessKey
			options          []ClientOption
		}
		want    *Client
		wantErr error
	}{
		{
			name: "new client",
			input: struct {
				appConfiguration string
				key              AccessKey
				options          []ClientOption
			}{
				appConfiguration: "config",
				key:              AccessKey{ID: "id", Secret: "secret"},
			},
			want: &Client{
				accessKey: AccessKey{
					ID:     "id",
					Secret: "secret",
				},
				cloud:       cloud.AzurePublic,
				scope:       "https://azconfig.io/.default",
				baseURL:     "https://config.azconfig.io/kv",
				userAgent:   "azcfg/" + version.Version(),
				concurrency: defaultConcurrency,
				timeout:     defaultTimeout,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewClientWithAccessKey(test.input.appConfiguration, test.input.key, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Client{}, mockCredential{}), cmpopts.IgnoreFields(Client{}, "c", "mu")); diff != "" {
				t.Errorf("NewClientWithAccessKey() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewClientWithAccessKey() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestNewClientWithConnectionString(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			connectionString string
			options          []ClientOption
		}
		want    *Client
		wantErr error
	}{
		{
			name: "new client",
			input: struct {
				connectionString string
				options          []ClientOption
			}{
				connectionString: "Endpoint=https://config.azconfig.io;Id=id;Secret=secret",
			},
			want: &Client{
				accessKey: AccessKey{
					ID:     "id",
					Secret: "secret",
				},
				cloud:       cloud.AzurePublic,
				scope:       "https://azconfig.io/.default",
				baseURL:     "https://config.azconfig.io/kv",
				userAgent:   "azcfg/" + version.Version(),
				concurrency: defaultConcurrency,
				timeout:     defaultTimeout,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewClientWithConnectionString(test.input.connectionString, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Client{}, mockCredential{}), cmpopts.IgnoreFields(Client{}, "c", "mu")); diff != "" {
				t.Errorf("NewClientWithConnectionString() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewClientWithConnectionString() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestClient_GetSettings(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			withAccessKey bool
			keys          []string
			options       []Option
			bodies        map[string][]byte
			label         string
			labels        map[string]string
			secrets       map[string]secret.Secret
			err           error
		}
		want    map[string]Setting
		wantErr error
	}{
		{
			name: "get settings",
			input: struct {
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
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
			name: "get settings - access key",
			input: struct {
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
			}{
				withAccessKey: true,
				keys:          []string{"setting-a", "setting-b", "setting-c"},
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
			name: "get settings with label",
			input: struct {
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
			}{
				keys: []string{"setting-a", "setting-b", "setting-c"},
				bodies: map[string][]byte{
					"setting-a": []byte(`{"value":"a"}`),
					"setting-b": []byte(`{"value":"b"}`),
					"setting-c": []byte(`{"value":"c"}`),
				},
				label: "prod",
				options: []Option{
					WithLabel("prod"),
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
			name: "get settings with labels",
			input: struct {
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
			}{
				keys: []string{"setting-a", "setting-b", "setting-c"},
				bodies: map[string][]byte{
					"setting-a": []byte(`{"value":"a"}`),
					"setting-b": []byte(`{"value":"b"}`),
					"setting-c": []byte(`{"value":"c"}`),
				},
				labels: map[string]string{
					"setting-a": "prod",
					"setting-c": "test",
				},
				options: []Option{
					WithLabels(map[string]string{
						"setting-a": "prod",
						"setting-c": "test",
					}),
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
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
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
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
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
			name: "setting forbidden",
			input: struct {
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
			}{
				keys: []string{"setting-a"},
				err:  errForbidden,
			},
			wantErr: settingError{
				StatusCode: http.StatusForbidden,
				Detail:     "access to key setting-a is forbidden",
			},
		},
		{
			name: "setting not found (key vault reference)",
			input: struct {
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
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
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
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
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
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
				withAccessKey bool
				keys          []string
				options       []Option
				bodies        map[string][]byte
				label         string
				labels        map[string]string
				secrets       map[string]secret.Secret
				err           error
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
			opts := []ClientOption{
				func(c *Client) {
					c.c = mockHttpClient{
						bodies: test.input.bodies,
						label:  test.input.label,
						labels: test.input.labels,
						err:    test.input.err,
					}
					c.sc = &mockSecretClient{
						secrets: test.input.secrets,
						err:     test.input.err,
					}
					c.timeout = time.Millisecond * 10
				},
			}
			var client *Client
			if !test.input.withAccessKey {
				client, _ = NewClient("config", mockCredential{}, opts...)
			} else {
				client, _ = NewClientWithAccessKey("config", AccessKey{ID: "id", Secret: base64.StdEncoding.EncodeToString([]byte(`secret`))}, opts...)
			}

			got, gotErr := client.GetSettings(context.Background(), test.input.keys, test.input.options...)

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
			newSecretClient = func(_ string, _ auth.Credential, _ ...secret.ClientOption) (secretClient, error) {
				return &mockSecretClient{
					secrets: test.input.secrets,
					err:     test.input.err,
				}, nil
			}

			client, _ := NewClient("config", mockCredential{}, func(c *Client) {
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
		wantErr error
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
		{
			name:    "faulty URL",
			input:   "not-a-url",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotVault, gotSecret, gotErr := vaultAndSecret(test.input)

			if test.want.vault != gotVault {
				t.Errorf("vaultAndSecret() = unexpected vault, want: %s, got: %s\n", test.want.vault, gotVault)
			}

			if test.want.secret != gotSecret {
				t.Errorf("vaultAndSecret() = unexpected secret, want: %s, got: %s\n", test.want.secret, gotSecret)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("vaultAndSecret() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestParseConnectionString(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  struct {
			appConfiguration string
			accessKey        AccessKey
		}
		wantErr error
	}{
		{
			name:  "parse connection string",
			input: "Endpoint=https://test.azconfig.io;Id=id;Secret=secret",
			want: struct {
				appConfiguration string
				accessKey        AccessKey
			}{
				appConfiguration: "test",
				accessKey:        AccessKey{ID: "id", Secret: "secret"},
			},
		},
		{
			name:  "parse connection string - missing key or value",
			input: "Endpoint=https://test.azconfig.io;Id=id;Secret",
			want: struct {
				appConfiguration string
				accessKey        AccessKey
			}{},
			wantErr: ErrParseConnectionString,
		},
		{
			name:  "parse connection string - missing secret",
			input: "Endpoint=https://test.azconfig.io;Id=id",
			want: struct {
				appConfiguration string
				accessKey        AccessKey
			}{},
			wantErr: ErrParseConnectionString,
		},
		{
			name:  "parse connection string - invalid endpoint",
			input: "Endpoint=invalid;Id=id;Secret=secret",
			want: struct {
				appConfiguration string
				accessKey        AccessKey
			}{},
			wantErr: ErrParseConnectionString,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotAppConfiguration, gotAccessKey, gotErr := parseConnectionString(test.input)

			if test.want.appConfiguration != gotAppConfiguration {
				t.Errorf("parseConnectionString() = unexpected appConfiguration, want: %s, got: %s\n", test.want.appConfiguration, gotAppConfiguration)
			}

			if diff := cmp.Diff(test.want.accessKey, gotAccessKey); diff != "" {
				t.Errorf("parseConnectionString() = unexpected accessKey (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("parseConnectionString() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestUri(t *testing.T) {
	var tests = []struct {
		name  string
		input cloud.Cloud
		want  string
	}{
		{
			name:  "azure public",
			input: cloud.AzurePublic,
			want:  "azconfig.io",
		},
		{
			name:  "azure government",
			input: cloud.AzureGovernment,
			want:  "azconfig.azure.us",
		},
		{
			name:  "azure china",
			input: cloud.AzureChina,
			want:  "azconfig.azure.cn",
		},
		{
			name:  "invalid",
			input: cloud.Cloud("invalid"),
			want:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := uri(test.input)

			if test.want != got {
				t.Errorf("uri() = unexpected result, want: %s, got: %s\n", test.want, got)
			}
		})
	}
}

func TestEndpoint(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			cloud            cloud.Cloud
			appConfiguration string
		}
		want string
	}{
		{
			name: "azure public",
			input: struct {
				cloud            cloud.Cloud
				appConfiguration string
			}{
				cloud:            cloud.AzurePublic,
				appConfiguration: "config",
			},
			want: "https://config.azconfig.io/kv",
		},
		{
			name: "azure government",
			input: struct {
				cloud            cloud.Cloud
				appConfiguration string
			}{
				cloud:            cloud.AzureGovernment,
				appConfiguration: "config",
			},
			want: "https://config.azconfig.azure.us/kv",
		},
		{
			name: "azure china",
			input: struct {
				cloud            cloud.Cloud
				appConfiguration string
			}{
				cloud:            cloud.AzureChina,
				appConfiguration: "config",
			},
			want: "https://config.azconfig.azure.cn/kv",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := endpoint(test.input.cloud, test.input.appConfiguration)

			if test.want != got {
				t.Errorf("endpoint() = unexpected result, want: %s, got: %s\n", test.want, got)
			}
		})
	}
}

func TestScope(t *testing.T) {
	var tests = []struct {
		name  string
		input cloud.Cloud
		want  string
	}{
		{
			name:  "azure public",
			input: cloud.AzurePublic,
			want:  "https://azconfig.io/.default",
		},
		{
			name:  "azure government",
			input: cloud.AzureGovernment,
			want:  "https://azconfig.azure.us/.default",
		},
		{
			name:  "azure china",
			input: cloud.AzureChina,
			want:  "https://azconfig.azure.cn/.default",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := scope(test.input)

			if test.want != got {
				t.Errorf("scope() = unexpected result, want: %s, got: %s\n", test.want, got)
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
	label  string
	labels map[string]string
}

func (c mockHttpClient) Do(req *http.Request) (*http.Response, error) {
	if c.err != nil && !errors.Is(c.err, errGetSecret) {
		if errors.Is(c.err, errServer) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"detail":"bad request","status":400}`))),
			}, nil
		}
		if errors.Is(c.err, errForbidden) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewBuffer([]byte(``))),
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

	label := req.URL.Query().Get("label")
	if len(c.label) > 0 && label != c.label {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"error":{}}`))),
		}, nil
	}

	l, ok := c.labels[name]
	if ok && len(l) != 0 && l != label {
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
	errRequest   = errors.New("request error")
	errForbidden = errors.New("forbidden")
	errServer    = errors.New("internal server error")
	errGetSecret = errors.New("error getting secret")
)

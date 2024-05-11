package secret

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
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewClient(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			vault   string
			cred    auth.Credential
			options []ClientOption
		}
		want    *Client
		wantErr error
	}{
		{
			name: "defaults",
			input: struct {
				vault   string
				cred    auth.Credential
				options []ClientOption
			}{
				vault: "vault",
				cred:  &mockCredential{},
			},
			want: &Client{
				cred:        &mockCredential{},
				cloud:       cloud.AzurePublic,
				scope:       "https://vault.azure.net/.default",
				baseURL:     "https://vault.vault.azure.net/secrets",
				vault:       "vault",
				userAgent:   "azcfg/" + version.Version(),
				concurrency: defaultConcurrency,
				timeout:     defaultTimeout,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewClient(test.input.vault, test.input.cred, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Client{}, mockCredential{}), cmpopts.IgnoreFields(Client{}, "c")); diff != "" {
				t.Errorf("NewClient() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewClient() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestClient_GetSecrets(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			names   []string
			bodies  map[string][]byte
			timeout time.Duration
			err     error
		}
		want    map[string]Secret
		wantErr error
	}{
		{
			name: "get secrets",
			input: struct {
				names   []string
				bodies  map[string][]byte
				timeout time.Duration
				err     error
			}{
				names: []string{"secret-a", "secret-b", "secret-c"},
				bodies: map[string][]byte{
					"secret-a": []byte(`{"value":"a"}`),
					"secret-b": []byte(`{"value":"b"}`),
					"secret-c": []byte(`{"value":"c"}`),
				},
				timeout: 30 * time.Millisecond,
			},
			want: map[string]Secret{
				"secret-a": {Value: "a"},
				"secret-b": {Value: "b"},
				"secret-c": {Value: "c"},
			},
			wantErr: nil,
		},
		{
			name: "secret not found",
			input: struct {
				names   []string
				bodies  map[string][]byte
				timeout time.Duration
				err     error
			}{
				names: []string{"secret-a", "secret-b", "secret-c"},
				bodies: map[string][]byte{
					"secret-a": []byte(`{"value":"a"}`),
					"secret-c": []byte(`{"value":"c"}`),
				},
				timeout: 30 * time.Millisecond,
			},
			want: map[string]Secret{
				"secret-a": {Value: "a"},
				"secret-b": {Value: ""},
				"secret-c": {Value: "c"},
			},
			wantErr: nil,
		},
		{
			name: "get secrets - context deadline exceeded",
			input: struct {
				names   []string
				bodies  map[string][]byte
				timeout time.Duration
				err     error
			}{
				names: []string{"secret-a", "secret-b", "secret-c"},
				bodies: map[string][]byte{
					"secret-a": []byte(`{"value":"a"}`),
					"secret-b": []byte(`{"value":"b"}`),
					"secret-c": []byte(`{"value":"c"}`),
				},
				timeout: 1 * time.Nanosecond,
			},
			wantErr: cmpopts.AnyError,
		},
		{
			name: "server error",
			input: struct {
				names   []string
				bodies  map[string][]byte
				timeout time.Duration
				err     error
			}{
				names:   []string{"secret-a"},
				timeout: 30 * time.Millisecond,
				err:     errServer,
			},
			want: nil,
			wantErr: secretError{
				Err: struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{
					Message: "bad request",
				},
				StatusCode: http.StatusBadRequest,
			},
		},
		{
			name: "request error",
			input: struct {
				names   []string
				bodies  map[string][]byte
				timeout time.Duration
				err     error
			}{
				names:   []string{"secret-a"},
				timeout: 30 * time.Millisecond,
				err:     errRequest,
			},
			want:    nil,
			wantErr: errRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := NewClient("vault", mockCredential{}, func(c *Client) {
				c.c = mockHttpClient{
					bodies: test.input.bodies,
					err:    test.input.err,
				}
				c.timeout = time.Millisecond * 10
			})

			ctx, cancel := context.WithTimeout(context.Background(), test.input.timeout)
			defer cancel()

			got, gotErr := client.GetSecrets(ctx, test.input.names)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("GetSecrets() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("GetSecrets() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestClient_Vault(t *testing.T) {
	t.Run("Vault()", func(t *testing.T) {
		want := "vault"
		client, _ := NewClient(want, mockCredential{})

		got := client.Vault()

		if want != got {
			t.Errorf("Vault() = unexpected result, want: %s, got: %s\n", want, got)
		}
	})

}

func TestClient_SetVault(t *testing.T) {
	t.Run("SetVault()", func(t *testing.T) {
		client, _ := NewClient("vault", mockCredential{})

		want := "new-vault"
		client.SetVault(want)
		got := client.Vault()

		if want != got {
			t.Errorf("SetVault() = unexpected result, want: %s, got: %s\n", want, got)
		}
	})
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
			want:  "vault.azure.net",
		},
		{
			name:  "azure government",
			input: cloud.AzureGovernment,
			want:  "vault.usgovcloudapi.net",
		},
		{
			name:  "azure china",
			input: cloud.AzureChina,
			want:  "vault.azure.cn",
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
			cloud cloud.Cloud
			vault string
		}
		want string
	}{
		{
			name: "azure public",
			input: struct {
				cloud cloud.Cloud
				vault string
			}{
				cloud: cloud.AzurePublic,
				vault: "vault",
			},
			want: "https://vault.vault.azure.net/secrets",
		},
		{
			name: "azure government",
			input: struct {
				cloud cloud.Cloud
				vault string
			}{
				cloud: cloud.AzureGovernment,
				vault: "vault",
			},
			want: "https://vault.vault.usgovcloudapi.net/secrets",
		},
		{
			name: "azure china",
			input: struct {
				cloud cloud.Cloud
				vault string
			}{
				cloud: cloud.AzureChina,
				vault: "vault",
			},
			want: "https://vault.vault.azure.cn/secrets",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := endpoint(test.input.cloud, test.input.vault)

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
			want:  "https://vault.azure.net/.default",
		},
		{
			name:  "azure government",
			input: cloud.AzureGovernment,
			want:  "https://vault.usgovcloudapi.net/.default",
		},
		{
			name:  "azure china",
			input: cloud.AzureChina,
			want:  "https://vault.azure.cn/.default",
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
	if c.err != nil {
		return auth.Token{}, c.err
	}
	return auth.Token{AccessToken: "ey1235"}, nil
}

type mockHttpClient struct {
	err    error
	bodies map[string][]byte
}

func (c mockHttpClient) Do(req *http.Request) (*http.Response, error) {
	time.Sleep(10 * time.Millisecond)
	if c.err != nil {
		if errors.Is(c.err, errServer) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"error":{"message":"bad request"}}`))),
			}, nil
		}
		return nil, c.err
	}

	name := path.Base(req.URL.Path)
	b, ok := c.bodies[name]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"error":{"code":"SecretNotFound"}}`))),
		}, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(b)),
	}, nil
}

var (
	errRequest = errors.New("request error")
	errServer  = errors.New("internal server error")
)

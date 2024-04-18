package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
			names  []string
			bodies map[string][]byte
			err    error
		}
		want    map[string]Secret
		wantErr error
	}{
		{
			name: "get secrets",
			input: struct {
				names  []string
				bodies map[string][]byte
				err    error
			}{
				names: []string{"secret-a", "secret-b", "secret-c"},
				bodies: map[string][]byte{
					"secret-a": []byte(`{"value":"a"}`),
					"secret-b": []byte(`{"value":"b"}`),
					"secret-c": []byte(`{"value":"c"}`),
				},
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
				names  []string
				bodies map[string][]byte
				err    error
			}{
				names: []string{"secret-a", "secret-b", "secret-c"},
				bodies: map[string][]byte{
					"secret-a": []byte(`{"value":"a"}`),
					"secret-c": []byte(`{"value":"c"}`),
				},
			},
			want: map[string]Secret{
				"secret-a": {Value: "a"},
				"secret-b": {Value: ""},
				"secret-c": {Value: "c"},
			},
			wantErr: nil,
		},
		{
			name: "server error",
			input: struct {
				names  []string
				bodies map[string][]byte
				err    error
			}{
				names: []string{"secret-a"},
				err:   errServer,
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
				names  []string
				bodies map[string][]byte
				err    error
			}{
				names: []string{"secret-a"},
				err:   errRequest,
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

			got, gotErr := client.GetSecrets(context.Background(), test.input.names)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("GetSecrets() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("GetSecrets() = unexpected error (-want +got)\n%s\n", diff)
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
	errServer  = fmt.Errorf("internal server error")
)

package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	errRequest = errors.New("request error")
	errServer  = fmt.Errorf("internal server error")
)

func TestClient_Get(t *testing.T) {
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
			wantErr: errorResponse{
				Err: errorResponseError{
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
			client := NewClient("vault", mockCredential{}, func(o *ClientOptions) {
				o.HTTPClient = mockHttpClient{
					bodies: test.input.bodies,
					err:    test.input.err,
				}
				o.Timeout = time.Millisecond * 10
			})

			got, gotErr := client.Get(test.input.names...)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Get() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Get() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

type mockCredential struct {
	err error
}

func (c mockCredential) Token(ctx context.Context) (auth.Token, error) {
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

	name := filepath.Base(req.URL.Path)
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

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
	"github.com/KarlGW/azcfg/internal/request"
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
			name: "setting not found",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
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
			name: "server error",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				err     error
			}{
				keys: []string{"setting-a"},
				err:  errServer,
			},
			want: nil,
			wantErr: request.ErrorResponse{
				Err: request.ErrorResponseError{
					Message: "bad request",
				},
				StatusCode: http.StatusBadRequest,
			},
		},
		{
			name: "request error",
			input: struct {
				keys    []string
				options []Option
				bodies  map[string][]byte
				err     error
			}{
				keys: []string{"setting-a"},
				err:  errRequest,
			},
			want:    nil,
			wantErr: errRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewClient("config", mockCredential{}, func(cl *Client) {
				cl.c = mockHttpClient{
					bodies: test.input.bodies,
					err:    test.input.err,
				}
				cl.timeout = time.Millisecond * 10
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

type mockCredential struct {
	err error
}

func (c mockCredential) Token(ctx context.Context) (auth.Token, error) {
	if c.err != nil {
		return auth.Token{}, c.err
	}
	return auth.Token{AccessToken: "ey1235"}, nil
}

func (c mockCredential) Scope() string {
	return ""
}

func (c mockCredential) SetScope(scope string) {}

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
			Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"error":{}}`))),
		}, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(b)),
	}, nil
}
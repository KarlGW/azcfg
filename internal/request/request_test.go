package request

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestDo(t *testing.T) {
	type input struct {
		client  Client
		headers http.Header
		method  string
		url     string
		body    []byte
	}

	var tests = []struct {
		name    string
		input   input
		want    Response
		wantErr error
	}{
		{
			name: "successful GET",
			input: input{
				client: mockClient{},
				headers: http.Header{
					"Content-Type": []string{"application/json"},
				},
				method: http.MethodGet,
				url:    "http://example.com",
			},
			want: Response{
				StatusCode: http.StatusOK,
				Body:       []byte(`{"message":"hello"}`),
			},
		},
		{
			name: "successful POST",
			input: input{
				client: mockClient{},
				headers: http.Header{
					"Content-Type": []string{"application/json"},
				},
				method: http.MethodPost,
				url:    "http://example.com",
				body:   []byte(`{"message":"hello"}`),
			},
			want: Response{
				StatusCode: http.StatusCreated,
				Body:       []byte(``),
			},
		},
		{
			name: "error",
			input: input{
				client: mockClient{
					err: errRequest,
				},
				headers: http.Header{
					"Content-Type": []string{"application/json"},
				},
				method: http.MethodGet,
				url:    "http://example.com",
			},
			wantErr: errRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := Do(context.Background(), test.input.client, test.input.headers, test.input.method, test.input.url, test.input.body)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Do() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Do() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

type mockClient struct {
	err error
}

func (c mockClient) Do(req *http.Request) (*http.Response, error) {
	if c.err != nil && errors.Is(c.err, errRequest) {
		return nil, c.err
	}

	if req.Method == http.MethodGet {
		if errors.Is(c.err, errNotFound) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"message":"hello"}`))),
		}, nil
	}
	if req.Method == http.MethodPost {
		if errors.Is(c.err, errBadRequest) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewReader([]byte(``))),
		}, nil
	}

	return nil, nil
}

var (
	errRequest    = errors.New("request error")
	errNotFound   = errors.New("not found")
	errBadRequest = errors.New("bad request")
)

package request

import (
	"context"
	"io"
	"net/http"

	"github.com/KarlGW/azcfg/internal/httpr"
)

// Client is the interface that wraps around method Do.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Do performs a request with the provided arguments.
func Do(ctx context.Context, client Client, headers http.Header, method, url string, body []byte) (Response, error) {
	req, err := httpr.NewRequest(ctx, method, url, body)
	if err != nil {
		return Response{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v[0])
	}

	resp, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return Response{}, err
	}

	return Response{
		StatusCode: resp.StatusCode,
		Body:       b,
	}, nil
}

// Response represents an HTTP response.
type Response struct {
	Body       []byte
	StatusCode int
}

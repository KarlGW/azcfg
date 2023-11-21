package request

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// Client is the interface that wraps around method Do.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Do performs a request with the provided method and target url.
func Do(ctx context.Context, client Client, headers http.Header, method, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v[0])
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, errors.New("no body")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusNoContent {
		return nil, Error{StatusCode: resp.StatusCode, Body: b}
	}

	return b, nil
}

// Error represents an error response from requests.
type Error struct {
	StatusCode int
	Body       []byte
}

// Error returns the body of the Error.
func (e Error) Error() string {
	return string(e.Body)
}

package request

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

var (
	// ErrNotFound is returned when a resource is not found.
	ErrNotFound = errors.New("not found")
)

// Client is the interface that wraps around method Do.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Do performs a request with the provided method and target url.
func Do(ctx context.Context, client Client, headers http.Header, method, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, ErrNotFound
		default:
			e := ErrorResponse{StatusCode: resp.StatusCode}
			if len(b) > 0 {
				if err := json.Unmarshal(b, &e); err != nil {
					return nil, err
				}
			}
			return nil, e
		}
	}

	return b, nil
}

// ErrorRespone represents an error response from Key Vault actions.
type ErrorResponse struct {
	Err        ErrorResponseError `json:"error"`
	StatusCode int
}

// ErrorResponseError represents the inner error in an error response.
type ErrorResponseError struct {
	Message string `json:"message"`
}

// Error returns the inner error message or errorResponse.
func (e ErrorResponse) Error() string {
	return e.Err.Message
}

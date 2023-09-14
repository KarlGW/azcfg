package secret

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

var (
	errSecretNotFound = errors.New("not found")
)

// request performs a request with the provided method and target url.
func request(ctx context.Context, client httpClient, headers http.Header, method, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, strings.Join(v, ";"))
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
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusNoContent {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, errSecretNotFound
		default:
			var e errorResponse
			if err := json.Unmarshal(b, &e); err != nil {
				return nil, err
			}
			e.StatusCode = resp.StatusCode
			return nil, e
		}
	}

	return b, nil
}

// authHeader returns headers containing
func addAuthHeader(headers http.Header, token string) http.Header {
	if headers == nil {
		headers = http.Header{}
	}
	headers.Add("Authorization", "Bearer "+token)
	return headers
}

// errorRespone represents an error response from Key Vault actions.
type errorResponse struct {
	Err        errorResponseError `json:"error"`
	StatusCode int
}

// errorResponseError represents the inner error in an error response.
type errorResponseError struct {
	Message string `json:"message"`
}

// Error returns the inner error message or errorResponse.
func (e errorResponse) Error() string {
	return e.Err.Message
}

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/KarlGW/azcfg/auth"
)

var (
	// ErrEmptyTokenResponse is returned when the response from a token request
	// is empty.
	ErrEmptyTokenResponse = errors.New("empty token response")
	// ErrTokenResponse is an erroneous token request.
	ErrTokenResponse = errors.New("token response error")
)

// authResult represents a token response from the authentication
// endpoint for Azure.
type authResult struct {
	AccessToken string `json:"access_token"`
	// ExpiresIn is amount of seconds until the token expires.
	// The reason any is used is that in earler API versions
	// as used by IMDS backed managed identities a string is
	// returned, whereas in newer a number is returned.
	ExpiresIn any `json:"expires_in"`
}

// authError represents an error response from the
// authentication endpoint for Azure.
type authError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// tokenFromAuthResult returns an auth.Token from an authResult.
func tokenFromAuthResult(t authResult) auth.Token {
	var expiresIn int
	switch e := t.ExpiresIn.(type) {
	case string:
		expiresIn, _ = strconv.Atoi(e)
	case float64:
		expiresIn = int(e)
	case int:
		expiresIn = e
	default:
		expiresIn = 0
	}
	return auth.Token{
		AccessToken: t.AccessToken,
		ExpiresOn:   time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
}

// request perform a request and return an authResult.
func request(c httpClient, req *http.Request) (authResult, error) {
	resp, err := c.Do(req)
	if err != nil {
		return authResult{}, err
	}
	if resp.Body == nil {
		return authResult{}, ErrEmptyTokenResponse
	}
	defer resp.Body.Close()

	// Read the body from the request.
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return authResult{}, err
	}

	if resp.StatusCode != http.StatusOK {
		var e authError
		if err := json.Unmarshal(b, &e); err != nil {
			return authResult{}, err
		}
		return authResult{}, fmt.Errorf("%w: %s", ErrTokenResponse, e.ErrorDescription)
	}

	var r authResult
	if err := json.Unmarshal(b, &r); err != nil {
		return authResult{}, err
	}
	return r, nil
}

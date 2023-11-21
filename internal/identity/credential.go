package identity

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/request"
)

var (
	// ErrEmptyTokenResponse is returned when the response from a token request
	// is empty.
	ErrEmptyTokenResponse = errors.New("empty token response")
	// ErrTokenResponse is an erroneous token request.
	ErrTokenResponse = errors.New("token response error")
	// ErrInvalidTenantID is returned when an invalid Tenant ID is provided.
	ErrInvalidTenantID = errors.New("invalid tenant ID")
	// ErrInvalidClientID is returned when an invalid Client ID is provided.
	ErrInvalidClientID = errors.New("invalid client ID")
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
	Code             string `json:"error"`
	ErrorDescription string `json:"error_description"`
	StatusCode       int
}

// Error returns the ErrorDescription of authError.
func (e authError) Error() string {
	return e.ErrorDescription
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

// shouldRetry contains retry policy for token requests.
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	var e request.Error
	if errors.As(err, &e) {
		if e.StatusCode == 0 || e.StatusCode >= http.StatusInternalServerError {
			return true
		}
		return false
	}
	return false
}

// validGUID checks if the provided string is a valid GUID.
func validGUID(s string) bool {
	return regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`).MatchString(s)
}

// validManagedIdentityResourceID checks if the provided string is a valid
// managed identity resource ID.
func validManagedIdentityResourceID(s string) bool {
	return regexp.MustCompile(`^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/resourcegroups/[a-zA-Z0-9-.]+/providers/microsoft.managedidentity/userassignedidentities/[a-zA-Z0-9]+`).MatchString(strings.ToLower(s))
}

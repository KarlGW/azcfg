package azcfg

import (
	"errors"
	"strings"

	"github.com/KarlGW/azcfg/internal/secret"
)

var (
	// ErrVaultNotSet is returned when no vault is set.
	ErrVaultNotSet = errors.New("a vault must be set")
)

// RequiredError represents an error when a secret is required.
type RequiredError struct {
	secret  string
	message string
}

// Error implements interface error.
func (e *RequiredError) Error() string {
	return e.message
}

// setMessage sets the message of *RequiredError.
func (e *RequiredError) setMessage(secrets map[string]secret.Secret, required []string) error {
	e.message = requiredErrorMessage(secrets, required)
	return e
}

// requiredErrorMessage builds a message based on the provided map[string]string (secrets)
// and []string (required).
func requiredErrorMessage(secrets map[string]secret.Secret, required []string) string {
	if len(required) == 0 {
		return ""
	}

	req := make([]string, 0)
	l := 0
	for _, r := range required {
		if len(secrets[r].Value) == 0 {
			req = append(req, r)
			l++
		}
	}

	var message strings.Builder
	if l == 1 {
		message.WriteString("secret: " + req[0] + " is required")
		return message.String()
	}
	message.WriteString("secrets: ")
	for i, r := range req {
		message.WriteString(r)
		if i < l-1 && l > 2 && i != l-2 {
			message.WriteString(", ")
		}
		if i == l-2 {
			message.WriteString(" and ")
		}
	}
	message.WriteString(" are required")
	return message.String()
}

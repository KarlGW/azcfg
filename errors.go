package azcfg

import (
	"errors"
	"strings"

	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
)

var (
	// ErrKeyVaultNotSet is returned when no vault is set.
	ErrKeyVaultNotSet = errors.New("a vault must be set")
)

// RequiredError represents an error when a secret is required.
type RequiredError struct {
	value   string
	message string
}

// Error implements interface error.
func (e *RequiredError) Error() string {
	return e.message
}

// setSecretMessage sets the message of *RequiredError.
func (e *RequiredError) setSecretMessage(secrets map[string]secret.Secret, required []string) error {
	if len(e.message) != 0 {
		e.message += ". "
	}
	e.message = requiredErrorMessage(secrets, required, "secret")
	return e
}

func (e *RequiredError) setSettingMessage(settings map[string]setting.Setting, required []string) error {
	if len(e.message) != 0 {
		e.message += ". "
	}
	e.message = requiredErrorMessage(settings, required, "setting")
	return e
}

// requiredErrorMessage builds a message based on the provided map[string]V (HasValue)
// and []string (required).
func requiredErrorMessage[V HasValue](values map[string]V, required []string, t string) string {
	if len(required) == 0 {
		return ""
	}

	req := make([]string, 0)
	l := 0
	for _, r := range required {
		if len(values[r].GetValue()) == 0 {
			req = append(req, r)
			l++
		}
	}

	var message strings.Builder
	if l == 1 {
		message.WriteString(t + ": " + req[0] + " is required")
		return message.String()
	}
	message.WriteString(t + "s: ")
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

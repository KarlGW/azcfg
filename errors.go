package azcfg

import (
	"errors"
	"strings"
)

var (
	// errRequired is returned when a secret/setting is required.
	errRequired = errors.New("required")
)

var (
	// ErrSetValue is returned when a value cannot be set.
	ErrSetValue = errors.New("set value error")
	// ErrCredential is returned when a credential error occurs.
	ErrCredential = errors.New("credential error")
	// ErrSecretClient is returned when a secret client error occurs.
	ErrSecretClient = errors.New("secret client error")
	// ErrSecretRetrieval is returned when a secret retrieval error occurs.
	ErrSecretRetrieval = errors.New("secret retrieval error")
	// ErrSettingClient is returned when a setting client error occurs.
	ErrSettingClient = errors.New("setting client error")
	// ErrSettingRetrieval is returned when a setting retrieval error occurs.
	ErrSettingRetrieval = errors.New("setting retrieval error")
)

// Error represents a general error type that can contain multiple errors
// for azcfg.
type Error struct {
	errors []error
}

// Error returns the combined error messages from the errors
// contained in Error.
func (e Error) Error() string {
	var errs []string
	for _, err := range e.errors {
		errs = append(errs, err.Error())
	}
	return strings.Join(errs, "\n")
}

// Errors returns the errors contained in Error.
func (e Error) Errors() []error {
	return e.errors
}

// Len returns the number of errors contained in Error.
func (e Error) Len() int {
	return len(e.errors)
}

// Has returns true if the provided error type is found in the errors.
// If found, the first error of the provided type is returned.
func (e Error) Has(err error) (error, bool) {
	for _, e := range e.errors {
		if errors.Is(e, err) {
			return e, true
		}
	}
	return nil, false
}

// RequiredFieldsError represents an error when either secrets or settings
// are required but not set.
type RequiredFieldsError struct {
	errors []error
}

// Error returns the combined error messages from the errors
// contained in RequiredFieldsError.
func (e RequiredFieldsError) Error() string {
	var msgs []string
	for _, err := range e.errors {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "\n")
}

// requiredSecretsError represents an error when secrets are required
// but not set.
type requiredSecretsError struct {
	message string
}

// Error returns the message set in requiredSecretsError.
func (e requiredSecretsError) Error() string {
	return e.message
}

// requiredSettingsError represents an error when settings are required
// but not set.
type requiredSettingsError struct {
	message string
}

// Error returns the message set in requiredSettingsError.
func (e requiredSettingsError) Error() string {
	return e.message
}

// requiredErrorMessage builds a message based on the provided map[string]V (HasValue)
// and []string (required).
func requiredErrorMessage[V hasValue](values map[string]V, required []string, t string) string {
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

// buildErr builds the resulting error and returns it.
func buildErr(errs ...error) error {
	if len(errs) == 0 {
		return nil
	}

	var reqErr RequiredFieldsError
	var e Error
	for _, err := range errs {
		var reqSecretsErr requiredSecretsError
		var reqSettingsErr requiredSettingsError
		if errors.As(err, &reqSecretsErr) || errors.As(err, &reqSettingsErr) {
			reqErr.errors = append(reqErr.errors, err)
		} else {
			e.errors = append(e.errors, err)
		}
	}
	if len(reqErr.errors) > 0 {
		return reqErr
	}
	return e
}

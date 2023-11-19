package azcfg

import (
	"errors"
	"strings"
)

var (
	// errRequired is returned when a secret/setting is required.
	errRequired = errors.New("required")
)

// RequiredFieldsError represents an error when either secrets or settings
// are required but not set.
type RequiredFieldsError struct {
	errors []error
}

// Error returns the combined error messages from the errors
// contained in RequiredFieldsError.
func (e *RequiredFieldsError) Error() string {
	var msgs []string
	for _, err := range e.errors {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "\n")
}

// requiredSecretsError represents an error when a secret is required
// but not set.
type requiredSecretsError struct {
	message string
}

// Error returns the message set in requiredSecretsError.
func (e requiredSecretsError) Error() string {
	return e.message
}

// requiredSettingsError represents an error when a secret is required
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

// buildErr builds the resulting error and returns it.
func buildErr(errs ...error) error {
	if len(errs) == 0 {
		return nil
	}
	var reqErr *RequiredFieldsError
	var msgs []string
	for _, err := range errs {
		if errors.Is(err, requiredSecretsError{}) || errors.Is(err, requiredSettingsError{}) {
			if reqErr == nil {
				reqErr = &RequiredFieldsError{
					errors: []error{err},
				}
			} else {
				reqErr.errors = append(reqErr.errors, err)
			}
		} else {
			msgs = append(msgs, err.Error())
		}
	}
	if reqErr != nil {
		return reqErr
	}
	return errors.New(strings.Join(msgs, "\n"))
}

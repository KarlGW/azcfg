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
func (e *Error) Error() string {
	var errs []string
	for _, err := range e.errors {
		errs = append(errs, err.Error())
	}
	return strings.Join(errs, "\n")
}

// Errors returns the errors contained in Error.
func (e *Error) Errors() []error {
	return e.errors
}

// newError creates a new Error with the provided errors.
func newError(errs ...error) *Error {
	if len(errs) == 0 {
		return nil
	}

	e := &Error{}
	e.errors = append(e.errors, errs...)
	return e
}

// RequiredFieldsError represents an error when either secrets or settings
// are required but not set.
type RequiredFieldsError struct {
	message  string
	required []string
	missing  []string
}

// Error returns the combined error messages from the errors
// contained in RequiredFieldsError.
func (e *RequiredFieldsError) Error() string {
	return e.message
}

// Required returns the fields that are required.
func (e *RequiredFieldsError) Required() []string {
	return e.required
}

// Missing returns the fields that are missing the required values.
func (e *RequiredFieldsError) Missing() []string {
	return e.missing
}

// newRequiredFieldsError creates a new RequiredFieldsError.
func newRequiredFieldsError(values map[string]string, requiredFields ...requiredFields) *RequiredFieldsError {
	if len(requiredFields) == 0 {
		return nil
	}

	var messages []string
	var required []string
	var missing []string
	for _, rfs := range requiredFields {
		if len(rfs.f) == 0 {
			continue
		}
		required = append(required, rfs.f...)
		l := 0
		mfs := make([]string, 0)
		for _, r := range rfs.f {
			if len(values[r]) == 0 {
				mfs = append(mfs, r)
				l++
			}
		}
		missing = append(missing, mfs...)

		var message strings.Builder
		if l == 1 {
			message.WriteString(rfs.t + ": " + mfs[0] + " is required")
		} else {
			message.WriteString(rfs.t + "s: ")
			for i, r := range mfs {
				message.WriteString(r)
				if i < l-1 && l > 2 && i != l-2 {
					message.WriteString(", ")
				}
				if i == l-2 {
					message.WriteString(" and ")
				}
			}
			message.WriteString(" are required")
		}
		messages = append(messages, message.String())
	}

	return &RequiredFieldsError{
		message:  strings.Join(messages, "\n"),
		required: required,
		missing:  missing,
	}
}

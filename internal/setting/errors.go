package setting

import (
	"errors"
)

const (
	// SettingForbidden is the status code returned when a setting is forbidden.
	SettingForbidden = 403
	// SettingNotFound is the status code returned when a setting is not found.
	SettingNotFound = 404
)

var (
	// ErrEmptyAppConfigurationName is returned when an empty app configuration name is provided.
	ErrEmptyAppConfigurationName = errors.New("app configration name cannot be empty")
	// ErrNilCredential is returned when credential is nil.
	ErrNilCredential = errors.New("credential cannot be nil")
	// ErrNoCredential is returned when no credential is provided.
	ErrNoCredential = errors.New("no credential provided")
	// ErrMissingAccessKeyID is returned when an access key ID is missing.
	ErrMissingAccessKeyID = errors.New("missing access key ID")
	// ErrMissingAccessKeySecret is returned when an access key secret is missing.
	ErrMissingAccessKeySecret = errors.New("missing access key secret")
	// ErrParseSecretURL is returned when a secret URL cannot be parsed.
	ErrParseSecretURL = errors.New("failed to parse secret URL")
	// ErrParseConnectionString is returned when a connection string cannot be parsed.
	ErrParseConnectionString = errors.New("failed to parse connection string")
)

// settingError represents an error returned from the App Configuration
// REST API.
type settingError struct {
	Type       string `json:"type"`
	Title      string `json:"title"`
	Name       string `json:"name"`
	Detail     string `json:"detail"`
	Status     int    `json:"status"`
	StatusCode int
}

// Error returns the detail from the settingError.
func (e settingError) Error() string {
	return e.Detail
}

// newSettingError creates a new settingError with the provided key and status code.
func newSettingError(key string, statusCode int) settingError {
	var detail string
	switch statusCode {
	case SettingForbidden:
		detail = "access to key " + key + " is forbidden"
	}
	return settingError{
		Detail:     detail,
		StatusCode: statusCode,
	}
}

// isSettingNotFound checks if the provided error is a settingError with
// the status code 404.
func isSettingNotFound(err error) bool {
	var settingErr settingError
	if errors.As(err, &settingErr) {
		if settingErr.StatusCode == SettingNotFound {
			return true
		}
	}
	return false
}

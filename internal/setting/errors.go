package setting

import (
	"errors"
)

const (
	// SettingNotFound is the status code returned when a setting is not found.
	SettingNotFound = 404
)

var (
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
func newSettingError(statusCode int) settingError {
	var detail string
	switch statusCode {
	case 400:
		detail = "bad request"
	case 401:
		detail = "not authorized"
	case 403:
		detail = "forbidden"
	case 404:
		detail = "not found"
	case 500:
		detail = "internal server error"
	case 502:
		detail = "bad gateway"
	case 503:
		detail = "service unavailable"
	case 504:
		detail = "gateway timeout"
	default:
		detail = "unknown error"
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

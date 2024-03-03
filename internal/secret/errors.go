package secret

import "errors"

const (
	// SecretNotFound is the error code returned when a secret is not found.
	SecretNotFound = "SecretNotFound"
	// Unauthorized is the error code returned when a request is unauthorized.
	Unauthorized = "Unauthorized"
)

// secretError represents an error returned from the Key Vault REST API.
type secretError struct {
	Err struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	StatusCode int
}

// Error returns the message from the secretError.
func (e secretError) Error() string {
	return e.Err.Message
}

// isSecretNotFound checks if the provided error is a secretError with
// the error coode SecretNotFound.
func isSecretNotFound(err error) bool {
	var secretErr secretError
	if errors.As(err, &secretErr) {
		if secretErr.Err.Code == SecretNotFound {
			return true
		}
	}
	return false
}

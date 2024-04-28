package httpr

import (
	"math"
	"net/http"
	"time"
)

// Backoff provides delays between retries with backoff.
type Backoff func(delay, maxDelay time.Duration, retry int) time.Duration

// Retry is a function that takes an *http.Response and an error
// and evaluates if a retry should be done.
type Retry func(r *http.Response, err error) bool

// RetryPolicy contains rules for retries.
type RetryPolicy struct {
	Retry      Retry
	Backoff    Backoff
	MinDelay   time.Duration
	MaxDelay   time.Duration
	MaxRetries int
}

// IsZero returns true if the RetryPolicy is the zero value.
func (r RetryPolicy) IsZero() bool {
	return r.Retry == nil && r.Backoff == nil && r.MinDelay == 0 && r.MaxDelay == 0 && r.MaxRetries == 0
}

// defaultRetry is the default implementation of retry.
func defaultRetry(r *http.Response, err error) bool {
	if err != nil {
		return true
	}
	switch r.StatusCode {
	case 0, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// exponentialBackoff provides backoff with an increasing delay from min delay,
// to max delay.
func exponentialBackoff(delay, maxDelay time.Duration, retry int) time.Duration {
	d := delay * time.Duration(math.Pow(2, float64(retry)))
	if d >= maxDelay {
		d = maxDelay
	}
	return d
}

// defaultRetryPolicy creates and returns a default policy.
func defaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MinDelay:   time.Millisecond * 500,
		MaxDelay:   time.Second * 5,
		MaxRetries: 3,
		Retry:      defaultRetry,
		Backoff:    exponentialBackoff,
	}
}

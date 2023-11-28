package httpr

import (
	"net/http"
	"time"
)

// WithTimeout sets the timeout of the *Client.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithTransport sets the transport for the *Client.
func WithTransport(transport *http.Transport) Option {
	return func(c *Client) {
		if transport != nil {
			c.transport = transport
		}
	}
}

// WithRetryPolicy sets retry policy for the *Client.
func WithRetryPolicy(retryPolicy RetryPolicy) Option {
	return func(c *Client) {
		c.retryPolicy = retryPolicy
	}
}

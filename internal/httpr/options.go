package httpr

import (
	"net/http"
	"time"
)

// WithTimeout sets the timeout of the *Client.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.to = d
	}
}

// WithTransport sets the transport (roundtripper) for
// the *Client.
func WithTransport(tr *http.Transport) Option {
	return func(c *Client) {
		c.tr = tr
	}
}

// WithRetryPolicy sets retry policy for the *Client.
func WithRetryPolicy(rp RetryPolicy) Option {
	return func(c *Client) {
		c.rp = rp
	}
}

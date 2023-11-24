package httpr

import (
	"net/http"
	"time"
)

// WithTimeout sets the timeout of the *Client.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.cl.Timeout = d
	}
}

// WithTransport sets the transport (roundtripper) for
// the *Client.
func WithTransport(tr *http.Transport) Option {
	return func(c *Client) {
		c.cl.Transport = tr
	}
}

package httpr

import (
	"io"
	"net/http"
	"time"
)

const (
	// defaultTimeout contains the default timeout of a *Client.
	defaultTimeout = 30 * time.Second
)

// Client wraps around a standard library *http.Client with
// added retry functionality.
type Client struct {
	cl          *http.Client
	transport   *http.Transport
	retryPolicy RetryPolicy
	timeout     time.Duration
}

// Option is a function that configures a *Client.
type Option func(c *Client)

// NewClient creates and returns a new *Client with the
// provided options.
func NewClient(options ...Option) *Client {
	c := &Client{
		timeout: defaultTimeout,
	}
	for _, option := range options {
		option(c)
	}
	if c.cl == nil {
		c.cl = &http.Client{
			Timeout: c.timeout,
		}
		if c.transport != nil {
			c.cl.Transport = c.transport
		}
	}
	if c.retryPolicy.IsZero() {
		c.retryPolicy = defaultRetryPolicy()
	}
	return c
}

// Do sends an HTTP request and returns an HTTP response.
func (c Client) Do(r *http.Request) (*http.Response, error) {
	if c.cl == nil {
		c.cl = &http.Client{}
	}
	if c.retryPolicy.Retry == nil {
		c.retryPolicy.Retry = func(r *http.Response, err error) bool {
			return false
		}
	}
	if c.retryPolicy.Backoff == nil {
		c.retryPolicy.Backoff = func(delay, maxDelay time.Duration, retry int) time.Duration {
			return 0
		}
	}

	retries := 0
	for {
		resp, err := c.cl.Do(r)
		if !c.retryPolicy.Retry(resp, err) || retries >= c.retryPolicy.MaxRetries {
			return resp, err
		}

		d := c.retryPolicy.Backoff(c.retryPolicy.MinDelay, c.retryPolicy.MaxDelay, retries)
		select {
		case <-time.After(d):
			retries++
			if err := drainResponse(resp); err != nil {
				return nil, err
			}
			if r.Body != nil && r.GetBody != nil {
				if err := resetRequest(r); err != nil {
					return nil, err
				}
			}
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
}

// resetRequest resets the request to be used before a
// retry.
func resetRequest(r *http.Request) error {
	req := r.Clone(r.Context())
	body, err := r.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	r = req
	return nil
}

// drainResponse drains the response body before a retry.
func drainResponse(r *http.Response) error {
	if r == nil {
		return nil
	}
	defer r.Body.Close()
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		return err
	}
	return nil
}

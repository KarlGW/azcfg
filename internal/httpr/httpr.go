package httpr

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"time"
)

const (
	// defaultTimeout contains the default timeout of a *Client.
	defaultTimeout = time.Second * 30
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
			Timeout: defaultTimeout,
		}
		if c.transport != nil {
			c.cl.Transport = c.transport
		}
	}
	if c.retryPolicy.isZero() {
		c.retryPolicy = defaultRetryPolicy()
	}
	return c
}

// Do sends an HTTP request and returns an HTTP response.
func (c Client) Do(r *http.Request) (*http.Response, error) {
	if r.Body != nil && r.GetBody == nil {
		if err := bufferRequestBody(r); err != nil {
			return nil, err
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

// bufferRequestBody reads the request body into a buffer
// and sets r.GetBody with the buffer to be used
// with retries.
func bufferRequestBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if err := r.Body.Close(); err != nil {
		return err
	}
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return nil
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

// RetryPolicy contains rules for retries.
type RetryPolicy struct {
	Retry      retry
	Backoff    backoff
	MinDelay   time.Duration
	MaxDelay   time.Duration
	MaxRetries int
}

// isZero returns true if the RetryPolicy is the zero value.
func (r RetryPolicy) isZero() bool {
	return r.Retry == nil && r.Backoff == nil && r.MinDelay == 0 && r.MaxDelay == 0 && r.MaxRetries == 0
}

// retry is a function that takes an *http.Response and an error
// and evaluates if a retry should be done.
type retry func(r *http.Response, err error) bool

// defaultRetry is the default implementation of retry.
func defaultRetry(r *http.Response, err error) bool {
	if err != nil {
		return true
	}
	switch r.StatusCode {
	case 0, http.StatusInternalServerError:
		return true
	}
	return false
}

// backoff provides delays between retries with backoff.
type backoff func(delay, maxDelay time.Duration, retry int) time.Duration

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

// NewRequest makes use of http.NewRequestWithContext and takes a []byte instead
// of a io.ReadCloser as a body. If the provided body is not empty it will
// set the GetBody function of the resulting request. This to prepare
// the request for retries as implemented by Do from the httpr.Client.
func NewRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return req, err
}

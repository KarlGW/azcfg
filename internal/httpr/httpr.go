package httpr

import (
	"bytes"
	"io"
	"math"
	"net/http"
	"time"
)

const (
	// defaultTimeout contains the default timeout of
	// a *Client.
	defaultTimout = time.Second * 30
)

// Client wraps around a standard library *http.Client with
// added retry functionality.
type Client struct {
	cl *http.Client
	rp RetryPolicy
	to time.Duration
	tr *http.Transport
}

// Option is a function that configures a *Client.
type Option func(c *Client)

// NewClient creates and returns a new *Client with the
// provided options
func NewClient(options ...Option) *Client {
	c := &Client{
		to: defaultTimout,
		rp: defaultRetryPolicy(),
	}
	for _, option := range options {
		option(c)
	}
	if c.cl == nil {
		c.cl = &http.Client{
			Timeout:   defaultTimout,
			Transport: c.tr,
		}
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
		if !c.rp.Retry(resp, err) || retries >= c.rp.MaxRetries {
			return resp, err
		}

		d := c.rp.Backoff(c.rp.MinDelay, c.rp.MaxDelay, retries)
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

// drainResponse drains the response body if before a retry.
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
	MinDelay   time.Duration
	MaxDelay   time.Duration
	MaxRetries int
	Retry      retry
	Backoff    backoff
}

// retry is a function that takes an error and returns
// true of alse based on the error.
type retry func(r *http.Response, err error) bool

func shouldRetry(r *http.Response, err error) bool {
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
		Retry:      shouldRetry,
		Backoff:    exponentialBackoff,
	}
}

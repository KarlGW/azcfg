// httpr provides a http client that implements retry with backoff.
// Inspired by and based on:
// https://medium.com/@nitishkr88/http-retries-in-go-e622e51d249f
// https://github.com/hashicorp/go-retryablehttp (See LICENSE-THIRD-PARTY in this repository)
package httpr

import (
	"bytes"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// HTTPClient is the interface that wraps around method Do.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client wraps around an HTTPClient and provides retries with backoff.
type Client struct {
	c                 HTTPClient
	maxRetries        uint8
	responseReadLimit int64
	header            http.Header
	minRetryTimeout   time.Duration
	maxRetryTimeout   time.Duration
	maxDuration       time.Duration
	backoff           backoff
	retry             retry
}

// Option is a function that sets options to a *Client.
type Option func(c *Client)

// NewClient creates and returns a new *Client.
func NewClient(options ...Option) *Client {
	c := &Client{
		c:               &http.Client{},
		header:          http.Header{},
		maxRetries:      3,
		maxDuration:     time.Second * 15,
		minRetryTimeout: time.Second * 1,
		maxRetryTimeout: time.Second * 10,
		retry:           defaultRetry,
		backoff:         defaultBackoff,
	}

	for _, option := range options {
		option(c)
	}

	return c
}

// Do sends an HTTP request and returns an HTTP respnse with built-in
// retries.
//
// Defaults:
// Max retry: 3
// Minimum retry timeout: 1 second
// Maximum retry timeout: 10 seconds.
// Backoff with a factor of 2.
func (c Client) Do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("a non-nil reuquest must be provided")
	}
	for k, v := range c.header {
		req.Header.Add(k, strings.Join(v, ", "))
	}

	r, err := newRequest(req)
	if err != nil {
		return nil, err
	}

	var attempt uint8 = 0
	deadline := time.Now().Add(c.maxDuration)
	for {
		// Check deadline.
		if time.Now().After(deadline) {
			return nil, errors.New("deadline for request exceeded")
		}
		// Get content length for inbetween retries.
		var cl int64
		var err error
		if r.body != nil {
			if cl, err = readAndRewind(r.body); err != nil {
				return nil, err
			} else {
				r.Request.ContentLength = cl
			}
		}

		resp, err := c.c.Do(r.Request)
		shouldRetry, retryErr := c.retry(resp, err)
		if !shouldRetry {
			if retryErr != nil {
				err = retryErr
			}
			return resp, err
		}

		if attempt == c.maxRetries {
			return resp, err
		}
		if resp != nil {
			if err := drain(resp.Body, c.responseReadLimit); err != nil {
				return resp, err
			}
		}

		time.Sleep(c.backoff(c.minRetryTimeout, c.maxRetryTimeout, attempt))
		attempt++
	}
}

// readAndRewind the provided io.ReadSeeker. It returns the total size
// of data read and an error if any.
func readAndRewind(rs io.ReadSeeker) (int64, error) {
	if rs == nil {
		return 0, nil
	}
	if size, err := rs.Seek(0, io.SeekEnd); err != nil {
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			return size, err
		}
		return size, err
	} else {
		return size, err
	}
}

// drain reads the provided io.ReadCloser to be able to reuse it.
func drain(rc io.ReadCloser, n int64) error {
	defer rc.Close()
	_, err := io.Copy(io.Discard, io.LimitReader(rc, n))
	if err != nil {
		return err
	}
	return nil
}

// newReadSeeker reads the body of the provided *http.Request and
// creates a new io.ReadSeeker with the data. It resets
// the body of the original request.
func newReadSeeker(r *http.Request) (io.ReadSeeker, error) {
	if r.Body == nil {
		return nil, nil
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.TeeReader(r.Body, &buf)); err != nil {
		return nil, err
	}
	if err := r.Body.Close(); err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(buf.Bytes()))

	return bytes.NewReader(buf.Bytes()), nil
}

// request wraps around the oririnal *http.Request and a new
// body of type io.ReadSeeker.
type request struct {
	body io.ReadSeeker
	*http.Request
}

// newRequest takes the provided *http.Requests and wraps it into
// a *request.
func newRequest(req *http.Request) (*request, error) {
	rs, err := newReadSeeker(req)
	if err != nil {
		return nil, err
	}

	return &request{
		body:    rs,
		Request: req,
	}, nil
}

// retry is a function that represents a retry policy.
type retry func(r *http.Response, err error) (bool, error)

// backoff is a function that represents a backoff policy.
type backoff func(min, max time.Duration, attempt uint8) time.Duration

// defaultRetry provides a default retry policy.
func defaultRetry(r *http.Response, err error) (bool, error) {
	if err != nil {
		return true, err
	}
	if r.StatusCode == 0 || r.StatusCode >= http.StatusInternalServerError {
		return true, nil
	}
	return false, nil
}

// defaultBackoff provides a default backoff policy.
func defaultBackoff(min, max time.Duration, attempt uint8) time.Duration {
	mult := math.Pow(2, float64(attempt)) * float64(min)
	sleep := time.Duration(mult)
	if float64(sleep) != mult || sleep > max {
		sleep = max
	}
	return sleep
}

// WithUserAgent sets the user agent of the client.
func WithUserAgent(s string) Option {
	return func(c *Client) {
		c.header.Add("User-Agent", s)
	}
}

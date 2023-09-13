package retry

import (
	"context"
	"math"
	"time"
)

// Policy contains rules for retries.
type Policy struct {
	MinDelay   time.Duration
	MaxDelay   time.Duration
	MaxRetries int
	Retry      retry
	Backoff    backoff
}

// PolicyOption sets a policy option.
type PolicyOption func(o *Policy)

// Do calls the provided function with the provided PolicyOption(s).
func Do(ctx context.Context, fn func() error, options ...PolicyOption) error {
	p := defaultPolicy()
	for _, option := range options {
		option(&p)
	}
	for i := 0; ; i++ {
		err := fn()
		if err == nil || i >= p.MaxRetries {
			return err
		}
		if !p.Retry(err) {
			return err
		}

		d := p.Backoff(p.MinDelay, p.MaxDelay, i)
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// retry is a function that returns true.
type retry func(err error) bool

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

// defaultPolicy creates and returns a default policy.
func defaultPolicy() Policy {
	return Policy{
		MinDelay:   time.Millisecond * 500,
		MaxDelay:   time.Second * 5,
		MaxRetries: 3,
		Retry: func(err error) bool {
			return true
		},
		Backoff: exponentialBackoff,
	}
}

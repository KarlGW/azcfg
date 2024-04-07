package setting

import (
	"time"

	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
)

// WithConcurrency sets the concurrency for setting retrieval.
func WithConcurrency(n int) ClientOption {
	return func(c *Client) {
		c.concurrency = n
	}
}

// WithTimeout sets timeout for setting retreival.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithLabel sets label on the on a setting request.
func WithLabel(label string) Option {
	return func(o *Options) {
		o.Label = label
	}
}

// WithRetryPolicy sets the retry policy for setting retrieval.
func WithRetryPolicy(r httpr.RetryPolicy) ClientOption {
	return func(c *Client) {
		c.retryPolicy = r
	}
}

// WithCloud sets the Azure cloud for setting retrieval.
func WithCloud(cloud cloud.Cloud) ClientOption {
	return func(c *Client) {
		c.cloud = cloud
	}
}

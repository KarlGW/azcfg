package secret

import (
	"time"

	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
)

// WithConcurrency sets the concurrency for secret retrieval.
func WithConcurrency(n int) ClientOption {
	return func(c *Client) {
		c.concurrency = n
	}
}

// WithTimeout sets timeout for secret retreival.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithRetryPolicy sets the retry policy for secret retrieval.
func WithRetryPolicy(r httpr.RetryPolicy) ClientOption {
	return func(c *Client) {
		c.retryPolicy = r
	}
}

// WithCloud sets the Azure cloud for secret retrieval.
func WithCloud(c cloud.Cloud) ClientOption {
	cl := c
	return func(c *Client) {
		if !cl.Valid() {
			cl = cloud.AzurePublic
		}
		c.cloud = cl
	}
}

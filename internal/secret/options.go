package secret

import (
	"time"

	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/request"
)

// WithHTTPClient sets the HTTP client for secret retrieval.
func WithHTTPClient(client request.Client) ClientOption {
	return func(c *Client) {
		c.c = client
	}
}

// WithConcurrency sets the concurrency for secret retrieval.
func WithConcurrency(n int) ClientOption {
	return func(c *Client) {
		c.concurrency = n
	}
}

// WithTimeout sets timeout for secret retrieval.
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

// WithClientVersions sets secret versions on the secret client based on the provided
// map. The key of the map should be the secret name, and the value
// should be the version.
func WithClientVersions(versions map[string]string) ClientOption {
	return func(c *Client) {
		c.versions = versions
	}
}

// WithVersions sets secret versions on the secret requests based on the provided
// map. The key of the map should be the secret name, and the value
// should be the version. Overrides the versions set on the client.
func WithVersions(versions map[string]string) Option {
	return func(o *Options) {
		o.Versions = versions
	}
}

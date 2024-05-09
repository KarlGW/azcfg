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

// WithRetryPolicy sets the retry policy for setting retrieval.
func WithRetryPolicy(r httpr.RetryPolicy) ClientOption {
	return func(c *Client) {
		c.retryPolicy = r
	}
}

// WithCloud sets the Azure cloud for setting retrieval.
func WithCloud(c cloud.Cloud) ClientOption {
	cl := c
	return func(c *Client) {
		if !cl.Valid() {
			cl = cloud.AzurePublic
		}
		c.cloud = cl
	}
}

// WithClientLabel sets label on the setting client.
func WithClientLabel(label string) ClientOption {
	return func(c *Client) {
		c.label = label
	}
}

// WithClientLabels sets labels on the setting client based on the provided
// map. The key of the map should be the setting name, and the value
// should be the label.
func WithClientLabels(labels map[string]string) ClientOption {
	return func(c *Client) {
		c.labels = labels
	}
}

// WithLabel sets label on the setting request. Overrides the client label.
func WithLabel(label string) Option {
	return func(o *Options) {
		o.Label = label
	}
}

// WithLabels sets labels on the setting requests based on the provided
// map. The key of the map should be the setting name, and the value
// should be the label. Overrides the client labels.
func WithLabels(labels map[string]string) Option {
	return func(o *Options) {
		o.Labels = labels
	}
}

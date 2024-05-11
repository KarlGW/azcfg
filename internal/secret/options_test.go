package secret

import (
	"testing"
	"time"

	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/google/go-cmp/cmp"
)

func TestClientOptions(t *testing.T) {
	var tests = []struct {
		name  string
		input ClientOption
		want  *Client
	}{
		{
			name:  "WithConcurrency",
			input: WithConcurrency(5),
			want: &Client{
				concurrency: 5,
			},
		},
		{
			name:  "WithTimeout",
			input: WithTimeout(5 * time.Second),
			want: &Client{
				timeout: 5 * time.Second,
			},
		},
		{
			name: "WithRetryPolicy",
			input: WithRetryPolicy(httpr.RetryPolicy{
				MaxRetries: 2,
			}),
			want: &Client{
				retryPolicy: httpr.RetryPolicy{
					MaxRetries: 2,
				},
			},
		},
		{
			name:  "WithCloud",
			input: WithCloud(cloud.AzurePublic),
			want: &Client{
				cloud: cloud.AzurePublic,
			},
		},
		{
			name:  "(invalid) WithCloud",
			input: WithCloud(cloud.Cloud("invalid")),
			want: &Client{
				cloud: cloud.AzurePublic,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := &Client{}
			test.input(got)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Client{})); diff != "" {
				t.Errorf("%s() = unexpected result (-want +got)\n%s\n", test.name, diff)
			}
		})
	}
}

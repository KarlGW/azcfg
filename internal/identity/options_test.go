package identity

import (
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestOptions(t *testing.T) {
	var tests = []struct {
		name  string
		input CredentialOption
		want  CredentialOptions
	}{
		{
			name:  "WithClientID",
			input: WithClientID("1111"),
			want: CredentialOptions{
				clientID: "1111",
			},
		},
		{
			name:  "WithResourceID",
			input: WithResourceID("2222"),
			want: CredentialOptions{
				resourceID: "2222",
			},
		},
		{
			name:  "WithSecret",
			input: WithSecret("3333"),
			want: CredentialOptions{
				secret: "3333",
			},
		},
		{
			name:  "WithCertificate",
			input: WithCertificate([]*x509.Certificate{_testCert1.Cert}, _testCert1.Key),
			want: CredentialOptions{
				certificates: []*x509.Certificate{_testCert1.Cert},
				key:          _testCert1.Key,
			},
		},
		{
			name:  "WithHTTPClient",
			input: WithHTTPClient(&http.Client{}),
			want: CredentialOptions{
				httpClient: &http.Client{},
			},
		},
		{
			name: "WithAssertion",
			input: WithAssertion(func() (string, error) {
				return "assertion", nil
			}),
		},
		{
			name:  "WithCloud",
			input: WithCloud(cloud.AzurePublic),
			want: CredentialOptions{
				cloud: cloud.AzurePublic,
			},
		},
		{
			name:  "WithCloud - invalid cloud",
			input: WithCloud("invalid"),
			want: CredentialOptions{
				cloud: cloud.AzurePublic,
			},
		},
		{
			name:  "WithIMDSDialTimeout",
			input: WithIMDSDialTimeout(time.Second * 5),
			want: CredentialOptions{
				dialTimeout: time.Second * 5,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CredentialOptions{}
			test.input(&got)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(CredentialOptions{}), cmpopts.IgnoreFields(CredentialOptions{}, "key"), cmp.Comparer(compareAssertionFunc)); diff != "" {
				t.Errorf("%s() = unexpected result (-want +got):\n%s", test.name, diff)
			}
		})
	}
}

package identity

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/internal/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestTokenFromAuthResult(t *testing.T) {
	var tests = []struct {
		name  string
		input authResult
		want  auth.Token
	}{
		{
			name: "ExpiresIn is string",
			input: authResult{
				AccessToken: "ey12345",
				ExpiresIn:   "3599",
			},
			want: auth.Token{
				AccessToken: "ey12345",
				ExpiresOn:   time.Now().Add(time.Duration(3599 * time.Second)),
			},
		},
		{
			name: "ExpiresIn is float64",
			input: authResult{
				AccessToken: "ey12345",
				ExpiresIn:   float64(3599),
			},
			want: auth.Token{
				AccessToken: "ey12345",
				ExpiresOn:   time.Now().Add(time.Duration(3599 * time.Second)),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := tokenFromAuthResult(test.input)

			if diff := cmp.Diff(test.want, got, cmpopts.EquateApproxTime(time.Second*5)); diff != "" {
				t.Errorf("tokenFromAuthResult() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

func setupHTTPClient(target string, _ error) request.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("tcp", target)
		},
	}
	return &http.Client{
		Transport: tr,
	}
}

var (
	_testTenantID, _       = uuid.New()
	_testClientID, _       = uuid.New()
	_testSubscriptionID, _ = uuid.New()
	_testClientSecret      = "12345"
	_testResourceID        = "/subscriptions/" + _testSubscriptionID + "/resourcegroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identity"
	_testScope             = "https://management.azure.com/.default"
)

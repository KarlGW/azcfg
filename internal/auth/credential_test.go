package auth

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/KarlGW/azcfg/internal/httpr"
)

var (
	_testTenantID     = "56757959-9916-4cd6-8b2f-df038fcc3c85"
	_testClientID     = "afb5e3e4-0fa1-4a22-aa35-6387dc0bc09d"
	_testClientSecret = "12345"
	_testResourceID   = "/subscriptions/93af3dd4-71ff-498e-ab46-7137dc2575e4/resourcegroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identity"
)

func setupHTTPClient(target string, err error) httpClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("tcp", target)
		},
	}
	return httpr.NewClient(httpr.WithTransport(tr))
}

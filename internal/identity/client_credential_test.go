package identity

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/httpr"
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/internal/testutils"
	"github.com/KarlGW/azcfg/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewClientCredential(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			tenantID string
			clientID string
			options  []CredentialOption
		}
		want    *ClientCredential
		wantErr error
	}{
		{
			name: "new client credential with secret",
			input: struct {
				tenantID string
				clientID string
				options  []CredentialOption
			}{
				tenantID: _testTenantID,
				clientID: _testClientID,
				options: []CredentialOption{
					WithSecret(_testClientSecret),
				},
			},
			want: &ClientCredential{
				c:         &http.Client{},
				tokens:    map[string]*auth.Token{},
				cloud:     cloud.AzurePublic,
				endpoint:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", _testTenantID),
				userAgent: "azcfg/" + version.Version(),
				tenantID:  _testTenantID,
				clientID:  _testClientID,
				secret:    _testClientSecret,
			},
			wantErr: nil,
		},
		{
			name: "invalid tenant ID",
			input: struct {
				tenantID string
				clientID string
				options  []CredentialOption
			}{
				tenantID: "1234",
				clientID: _testClientID,
				options:  []CredentialOption{},
			},
			want:    nil,
			wantErr: ErrInvalidTenantID,
		},
		{
			name: "invalid client ID",
			input: struct {
				tenantID string
				clientID string
				options  []CredentialOption
			}{
				tenantID: _testTenantID,
				clientID: "1234",
				options:  []CredentialOption{},
			},
			want:    nil,
			wantErr: ErrInvalidClientID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewClientCredential(test.input.tenantID, test.input.clientID, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(ClientCredential{}, certificate{}), cmpopts.IgnoreFields(ClientCredential{}, "c", "mu"), cmpopts.IgnoreFields(httpr.Client{}, "retryPolicy"), cmpopts.IgnoreFields(certificate{}, "key")); diff != "" {
				t.Errorf("NewClientCredential() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewClientCredential() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestNewClientSecretCredential(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			tenantID     string
			clientID     string
			clientSecret string
			options      []CredentialOption
		}
		want    *ClientCredential
		wantErr error
	}{
		{
			name: "new client credential with secret",
			input: struct {
				tenantID     string
				clientID     string
				clientSecret string
				options      []CredentialOption
			}{
				tenantID:     _testTenantID,
				clientID:     _testClientID,
				clientSecret: _testClientSecret,
				options:      []CredentialOption{},
			},
			want: &ClientCredential{
				c:         &http.Client{},
				tokens:    map[string]*auth.Token{},
				cloud:     cloud.AzurePublic,
				endpoint:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", _testTenantID),
				userAgent: "azcfg/" + version.Version(),
				tenantID:  _testTenantID,
				clientID:  _testClientID,
				secret:    _testClientSecret,
			},
		},
		{
			name: "invalid secret",
			input: struct {
				tenantID     string
				clientID     string
				clientSecret string
				options      []CredentialOption
			}{
				tenantID: _testTenantID,
				clientID: _testClientID,
				options:  []CredentialOption{},
			},
			wantErr: errors.New("client secret invalid"),
		},
	}

	for _, test := range tests {
		got, gotErr := NewClientSecretCredential(test.input.tenantID, test.input.clientID, test.input.clientSecret, test.input.options...)

		if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(ClientCredential{}, certificate{}), cmpopts.IgnoreFields(ClientCredential{}, "c", "mu"), cmpopts.IgnoreFields(httpr.Client{}, "retryPolicy"), cmpopts.IgnoreFields(certificate{}, "key")); diff != "" {
			t.Errorf("NewClientSecretCredential() = unexpected result (-want +got)\n%s\n", diff)
		}

		if test.wantErr == nil && gotErr != nil {
			t.Errorf("NewClientSecretCredential() = unexpected error (-want +got)\n%s\n", gotErr)
		}
	}
}

func TestNewClientCertificateCredential(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			tenantID     string
			clientID     string
			certificates []*x509.Certificate
			key          *rsa.PrivateKey
			options      []CredentialOption
		}
		want    *ClientCredential
		wantErr error
	}{
		{
			name: "new client credential with certificate",
			input: struct {
				tenantID     string
				clientID     string
				certificates []*x509.Certificate
				key          *rsa.PrivateKey
				options      []CredentialOption
			}{
				tenantID:     _testTenantID,
				clientID:     _testClientID,
				certificates: []*x509.Certificate{_testCert.Cert},
				key:          _testCert.RSAKey,
				options:      []CredentialOption{},
			},
			want: &ClientCredential{
				c:         &http.Client{},
				tokens:    map[string]*auth.Token{},
				cloud:     cloud.AzurePublic,
				endpoint:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", _testTenantID),
				userAgent: "azcfg/" + version.Version(),
				tenantID:  _testTenantID,
				clientID:  _testClientID,
				certificate: certificate{
					cert:       _testCert.Cert,
					key:        _testCert.RSAKey,
					thumbprint: _testCert.Thumbprint,
					x5c:        []string{base64.StdEncoding.EncodeToString(_testCert.Cert.Raw)},
				},
			},
		},
		{
			name: "invalid certificate",
			input: struct {
				tenantID     string
				clientID     string
				certificates []*x509.Certificate
				key          *rsa.PrivateKey
				options      []CredentialOption
			}{
				tenantID: _testTenantID,
				clientID: _testClientID,
				key:      _testCert.RSAKey,
				options:  []CredentialOption{},
			},
			wantErr: errors.New("client certificate invalid"),
		},
		{
			name: "invalid certificate key",
			input: struct {
				tenantID     string
				clientID     string
				certificates []*x509.Certificate
				key          *rsa.PrivateKey
				options      []CredentialOption
			}{
				tenantID:     _testTenantID,
				clientID:     _testClientID,
				certificates: []*x509.Certificate{_testCert.Cert},
				options:      []CredentialOption{},
			},
			wantErr: errors.New("client certificate key invalid"),
		},
	}

	for _, test := range tests {
		got, gotErr := NewClientCertificateCredential(test.input.tenantID, test.input.clientID, test.input.certificates, test.input.key, test.input.options...)

		if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(ClientCredential{}, certificate{}), cmpopts.IgnoreFields(ClientCredential{}, "c", "mu"), cmpopts.IgnoreFields(httpr.Client{}, "retryPolicy"), cmpopts.IgnoreFields(certificate{}, "key")); diff != "" {
			t.Errorf("NewClientCertificateCredential() = unexpected result (-want +got)\n%s\n", diff)
		}

		if test.wantErr == nil && gotErr != nil {
			t.Errorf("NewClientCertificateCredential() = unexpected error (-want +got)\n%s\n", gotErr)
		}
	}
}

func TestNewClientAssertionCredential(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			tenantID  string
			clientID  string
			assertion func() (string, error)
			options   []CredentialOption
		}
		want    *ClientCredential
		wantErr error
	}{
		{
			name: "new client credential with assertion",
			input: struct {
				tenantID  string
				clientID  string
				assertion func() (string, error)
				options   []CredentialOption
			}{
				tenantID: _testTenantID,
				clientID: _testClientID,
				assertion: func() (string, error) {
					return "assertion", nil
				},
				options: []CredentialOption{},
			},
			want: &ClientCredential{
				c:         &http.Client{},
				tokens:    map[string]*auth.Token{},
				cloud:     cloud.AzurePublic,
				endpoint:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", _testTenantID),
				userAgent: "azcfg/" + version.Version(),
				tenantID:  _testTenantID,
				clientID:  _testClientID,
				assertion: func() (string, error) {
					return "assertion", nil
				},
			},
		},
		{
			name: "invalid assertion",
			input: struct {
				tenantID  string
				clientID  string
				assertion func() (string, error)
				options   []CredentialOption
			}{
				tenantID: _testTenantID,
				clientID: _testClientID,
				options:  []CredentialOption{},
			},
			wantErr: errors.New("client assertion function invalid"),
		},
	}

	for _, test := range tests {
		got, gotErr := NewClientAssertionCredential(test.input.tenantID, test.input.clientID, test.input.assertion, test.input.options...)

		if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(ClientCredential{}, certificate{}), cmpopts.IgnoreFields(ClientCredential{}, "c", "mu"), cmpopts.IgnoreFields(httpr.Client{}, "retryPolicy"), cmpopts.IgnoreFields(certificate{}, "key"), cmp.Comparer(compareAssertionFunc)); diff != "" {
			t.Errorf("NewClientAssertionCredential() = unexpected result (-want +got)\n%s\n", diff)
		}

		if test.wantErr == nil && gotErr != nil {
			t.Errorf("NewClientAssertionCredential() = unexpected error (-want +got)\n%s\n", gotErr)
		}
	}
}

func TestClientCredential_Token(t *testing.T) {
	var tests = []struct {
		name    string
		input   func(client request.Client) *ClientCredential
		want    auth.Token
		wantErr error
	}{
		{
			name: "get token (client secret)",
			input: func(client request.Client) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithHTTPClient(client))
				return cred
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
		},
		{
			name: "get token (client certificate)",
			input: func(client request.Client) *ClientCredential {
				cred, _ := NewClientCertificateCredential(_testTenantID, _testClientID, []*x509.Certificate{_testCert.Cert}, _testCert.RSAKey, WithHTTPClient(client))
				return cred
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
		},
		{
			name: "get token (client assertion)",
			input: func(client request.Client) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithAssertion(func() (string, error) {
					return "ey12345", nil
				}), WithHTTPClient(client))
				return cred
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
		},
		{
			name: "get token from cache",
			input: func(client request.Client) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithHTTPClient(client))
				cred.tokens[_testScope] = &auth.Token{
					AccessToken: "ey54321",
					ExpiresOn:   time.Now().Add(time.Hour),
				}
				return cred
			},
			want: auth.Token{
				AccessToken: "ey54321",
			},
			wantErr: nil,
		},
		{
			name: "get token from cache (expired)",
			input: func(client request.Client) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithHTTPClient(client))
				cred.tokens[_testScope] = &auth.Token{
					AccessToken: "ey54321",
					ExpiresOn:   time.Now().Add(time.Hour * -3),
				}
				return cred
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
			wantErr: nil,
		},
		{
			name: "error",
			input: func(client request.Client) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithHTTPClient(client))
				return cred
			},
			want:    auth.Token{},
			wantErr: authError{StatusCode: http.StatusBadRequest},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := setupClientCredentialHTTPServer(test.wantErr)
			defer ts.Close()

			client := setupHTTPClient(ts.Listener.Addr().String(), test.wantErr)
			cred := test.input(client)
			got, gotErr := cred.Token(context.Background(), func(o *auth.TokenOptions) {
				o.Scope = _testScope
			})

			if diff := cmp.Diff(test.want, got, cmpopts.IgnoreFields(auth.Token{}, "ExpiresOn")); diff != "" {
				t.Errorf("Token() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Token() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestEndpoint(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			cloud    cloud.Cloud
			tenantID string
		}
		want string
	}{
		{
			name: "public",
			input: struct {
				cloud    cloud.Cloud
				tenantID string
			}{
				cloud:    cloud.AzurePublic,
				tenantID: _testTenantID,
			},
			want: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", _testTenantID),
		},
		{
			name: "government",
			input: struct {
				cloud    cloud.Cloud
				tenantID string
			}{
				cloud:    cloud.AzureGovernment,
				tenantID: _testTenantID,
			},
			want: fmt.Sprintf("https://login.microsoftonline.us/%s/oauth2/v2.0/token", _testTenantID),
		},
		{
			name: "china",
			input: struct {
				cloud    cloud.Cloud
				tenantID string
			}{
				cloud:    cloud.AzureChina,
				tenantID: _testTenantID,
			},
			want: fmt.Sprintf("https://login.chinacloudapi.cn/%s/oauth2/v2.0/token", _testTenantID),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := endpoint(test.input.cloud, test.input.tenantID)

			if test.want != got {
				t.Errorf("endpoint() = unexpected result (-want +got)\n%s\n", cmp.Diff(test.want, got))
			}
		})
	}
}

func setupClientCredentialHTTPServer(err error) *httptest.Server {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			if errors.Is(err, authError{StatusCode: http.StatusBadRequest}) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"","error_description":""}`))
				return
			}
		}
		r.ParseForm()
		if len(r.FormValue("client_id")) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(r.FormValue("client_secret")) == 0 && len(r.FormValue("client_assertion")) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(r.FormValue("grant_type")) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(r.FormValue("scope")) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"ey12345","expires_in":3599}`))
	}))
	return ts
}

func compareAssertionFunc(x, y func() (string, error)) bool {
	if x == nil || y == nil {
		return true
	}
	xResult, xErr := x()
	yResult, yErr := y()
	return xResult == yResult && xErr == yErr
}

var (
	_testCert, _ = testutils.CreateCertificate()
)

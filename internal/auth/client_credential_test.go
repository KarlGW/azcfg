package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
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
			name: "new client credential with secret and scope",
			input: struct {
				tenantID string
				clientID string
				options  []CredentialOption
			}{
				tenantID: _testTenantID,
				clientID: _testClientID,
				options: []CredentialOption{
					WithSecret(_testClientSecret),
					WithScope(auth.Scopes[0]),
				},
			},
			want: &ClientCredential{
				c:            &http.Client{},
				endpoint:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", _testTenantID),
				tenantID:     _testTenantID,
				clientID:     _testClientID,
				clientSecret: _testClientSecret,
				scope:        auth.Scopes[0],
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

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(ClientCredential{}), cmpopts.IgnoreUnexported(http.Client{})); diff != "" {
				t.Errorf("NewClientCredential() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewClientCredential() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestClientCredential_Token(t *testing.T) {
	var tests = []struct {
		name    string
		input   func(client httpClient) *ClientCredential
		want    auth.Token
		wantErr error
	}{
		{
			name: "get token",
			input: func(client httpClient) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithScope(auth.Scopes[0]), WithHTTPClient(client))
				return cred
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
			wantErr: nil,
		},
		{
			name: "get token from cache",
			input: func(client httpClient) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithScope(auth.Scopes[0]), WithHTTPClient(client))
				cred.token = &auth.Token{
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
			input: func(client httpClient) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithScope(auth.Scopes[0]), WithHTTPClient(client))
				cred.token = &auth.Token{
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
			input: func(client httpClient) *ClientCredential {
				cred, _ := NewClientCredential(_testTenantID, _testClientID, WithSecret("1234"), WithScope(auth.Scopes[0]), WithHTTPClient(client))
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
			got, gotErr := cred.Token(context.Background())

			if diff := cmp.Diff(test.want, got, cmpopts.IgnoreFields(auth.Token{}, "ExpiresOn")); diff != "" {
				t.Errorf("Token() = unexpected result (-want +got)\n%s¶n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Token() = unexpected error (-want +got)\n%s\n", diff)
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
		if len(r.FormValue("client_secret")) == 0 {
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

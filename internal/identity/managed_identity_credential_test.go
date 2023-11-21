package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/request"
	"github.com/KarlGW/azcfg/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewManagedIdentityCredential(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			options []CredentialOption
			envs    map[string]string
		}
		want    *ManagedIdentityCredential
		wantErr error
	}{
		{
			name: "new managed identity credential (imds)",
			input: struct {
				options []CredentialOption
				envs    map[string]string
			}{
				options: []CredentialOption{},
				envs:    map[string]string{},
			},
			want: &ManagedIdentityCredential{
				c: &http.Client{},
				header: http.Header{
					"User-Agent": {"azcfg/" + version.Version()},
					"Metadata":   {"true"},
				},
				endpoint:   imdsEndpoint,
				apiVersion: imdsAPIVersion,
			},
			wantErr: nil,
		},
		{
			name: "new managed identity credential (imds) (client id)",
			input: struct {
				options []CredentialOption
				envs    map[string]string
			}{
				options: []CredentialOption{
					WithClientID(_testClientID),
				},
				envs: map[string]string{},
			},
			want: &ManagedIdentityCredential{
				c: &http.Client{},
				header: http.Header{
					"User-Agent": {"azcfg/" + version.Version()},
					"Metadata":   {"true"},
				},
				endpoint:   imdsEndpoint,
				apiVersion: imdsAPIVersion,
				clientID:   _testClientID,
			},
			wantErr: nil,
		},
		{
			name: "new managed identity credential (imds) (resource id)",
			input: struct {
				options []CredentialOption
				envs    map[string]string
			}{
				options: []CredentialOption{
					WithResourceID(_testResourceID),
				},
				envs: map[string]string{},
			},
			want: &ManagedIdentityCredential{
				c: &http.Client{},
				header: http.Header{
					"User-Agent": {"azcfg/" + version.Version()},
					"Metadata":   {"true"},
				},
				endpoint:   imdsEndpoint,
				apiVersion: imdsAPIVersion,
				resourceID: _testResourceID,
			},
			wantErr: nil,
		},
		{
			name: "new managed identity credential (app service)",
			input: struct {
				options []CredentialOption
				envs    map[string]string
			}{
				options: []CredentialOption{},
				envs: map[string]string{
					identityEndpoint: "ENDPOINT",
					identityHeader:   "12345",
				},
			},
			want: &ManagedIdentityCredential{
				c: &http.Client{},
				header: http.Header{
					"User-Agent":        {"azcfg/" + version.Version()},
					"X-Identity-Header": {"12345"},
				},
				endpoint:   "ENDPOINT",
				apiVersion: appServiceAPIVersion,
			},
			wantErr: nil,
		},
		{
			name: "new managed identity credential (invalid client id)",
			input: struct {
				options []CredentialOption
				envs    map[string]string
			}{
				options: []CredentialOption{
					WithClientID("1234"),
				},
				envs: map[string]string{},
			},
			want:    nil,
			wantErr: ErrInvalidClientID,
		},
		{
			name: "new managed identity credential (invalid resource id)",
			input: struct {
				options []CredentialOption
				envs    map[string]string
			}{
				options: []CredentialOption{
					WithResourceID("1234"),
				},
				envs: map[string]string{},
			},
			want:    nil,
			wantErr: ErrInvalidManagedIdentityResourceID,
		},
		{
			name: "new managed identity credential (unsupported)",
			input: struct {
				options []CredentialOption
				envs    map[string]string
			}{
				options: []CredentialOption{},
				envs: map[string]string{
					identityEndpoint: "ENDPOINT",
				},
			},
			want:    nil,
			wantErr: ErrUnsupportedManagedIdentityType,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnvVars(test.input.envs)
			defer unsetEnvVars(test.input.envs)

			got, gotErr := NewManagedIdentityCredential(test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(ManagedIdentityCredential{}), cmpopts.IgnoreUnexported(http.Client{}, ManagedIdentityCredential{})); diff != "" {
				t.Errorf("NewManagedIdentityCredential() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewManagedIdentityCredential() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestManagedIdentityCredential_Token(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			cred func(client request.Client) *ManagedIdentityCredential
			envs map[string]string
		}
		want struct {
			token auth.Token
			v     *url.Values
		}
		wantErr error
	}{
		{
			name: "get token (imds)",
			input: struct {
				cred func(client request.Client) *ManagedIdentityCredential
				envs map[string]string
			}{
				cred: func(client request.Client) *ManagedIdentityCredential {
					cred, _ := NewManagedIdentityCredential(WithHTTPClient(client))
					return cred
				},
			},
			want: struct {
				token auth.Token
				v     *url.Values
			}{
				token: auth.Token{
					AccessToken: "ey12345",
				},
				v: &url.Values{
					"api-version": {imdsAPIVersion},
					"resource":    {strings.TrimSuffix(string(_testScope), "/.default")},
				},
			},
			wantErr: nil,
		},
		{
			name: "get token from cache (imds)",
			input: struct {
				cred func(client request.Client) *ManagedIdentityCredential
				envs map[string]string
			}{
				cred: func(client request.Client) *ManagedIdentityCredential {
					cred, _ := NewManagedIdentityCredential(WithHTTPClient(client))
					cred.tokens[_testScope] = &auth.Token{
						AccessToken: "ey54321",
						ExpiresOn:   time.Now().Add(time.Hour),
					}
					return cred
				},
			},
			want: struct {
				token auth.Token
				v     *url.Values
			}{
				token: auth.Token{
					AccessToken: "ey54321",
				},
				v: &url.Values{
					"api-version": {imdsAPIVersion},
					"resource":    {strings.TrimSuffix(string(_testScope), "/.default")},
				},
			},
			wantErr: nil,
		},
		{
			name: "get token from cache (expired) (imds)",
			input: struct {
				cred func(client request.Client) *ManagedIdentityCredential
				envs map[string]string
			}{
				cred: func(client request.Client) *ManagedIdentityCredential {
					cred, _ := NewManagedIdentityCredential(WithHTTPClient(client))
					cred.tokens[_testScope] = &auth.Token{
						AccessToken: "ey54321",
						ExpiresOn:   time.Now().Add(time.Hour * -3),
					}
					return cred
				},
			},
			want: struct {
				token auth.Token
				v     *url.Values
			}{
				token: auth.Token{
					AccessToken: "ey12345",
				},
				v: &url.Values{
					"api-version": {imdsAPIVersion},
					"resource":    {strings.TrimSuffix(string(_testScope), "/.default")},
				},
			},
			wantErr: nil,
		},
		{
			name: "get token (imds) (client id)",
			input: struct {
				cred func(client request.Client) *ManagedIdentityCredential
				envs map[string]string
			}{
				cred: func(client request.Client) *ManagedIdentityCredential {
					cred, _ := NewManagedIdentityCredential(WithHTTPClient(client), WithClientID(_testClientID))
					return cred
				},
			},
			want: struct {
				token auth.Token
				v     *url.Values
			}{
				token: auth.Token{
					AccessToken: "ey12345",
				},
				v: &url.Values{
					"api-version": {imdsAPIVersion},
					"resource":    {strings.TrimSuffix(string(_testScope), "/.default")},
					"client_id":   {_testClientID},
				},
			},
			wantErr: nil,
		},
		{
			name: "get token (imds) (resource id)",
			input: struct {
				cred func(client request.Client) *ManagedIdentityCredential
				envs map[string]string
			}{
				cred: func(client request.Client) *ManagedIdentityCredential {
					cred, _ := NewManagedIdentityCredential(WithHTTPClient(client), WithResourceID(_testResourceID))
					return cred
				},
			},
			want: struct {
				token auth.Token
				v     *url.Values
			}{
				token: auth.Token{
					AccessToken: "ey12345",
				},
				v: &url.Values{
					"api-version": {imdsAPIVersion},
					"resource":    {strings.TrimSuffix(string(_testScope), "/.default")},
					"mi_res_id":   {_testResourceID},
				},
			},
			wantErr: nil,
		},
		{
			name: "error",
			input: struct {
				cred func(client request.Client) *ManagedIdentityCredential
				envs map[string]string
			}{
				cred: func(client request.Client) *ManagedIdentityCredential {
					cred, _ := NewManagedIdentityCredential(WithHTTPClient(client))
					return cred
				},
			},
			want: struct {
				token auth.Token
				v     *url.Values
			}{
				token: auth.Token{},
				v:     &url.Values{},
			},
			wantErr: authError{StatusCode: http.StatusBadRequest},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnvVars(test.input.envs)
			defer unsetEnvVars(test.input.envs)

			ts := setupManagedIdentityCredentialHTTPServer(test.want.v, test.wantErr)
			defer ts.Close()

			client := setupHTTPClient(ts.Listener.Addr().String(), test.wantErr)
			cred := test.input.cred(client)
			got, gotErr := cred.Token(context.Background(), func(o *auth.TokenOptions) {
				o.Scope = _testScope
			})

			if diff := cmp.Diff(test.want.token, got, cmpopts.IgnoreFields(auth.Token{}, "ExpiresOn")); diff != "" {
				t.Errorf("Token() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Token() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

func setupManagedIdentityCredentialHTTPServer(v *url.Values, err error) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			if errors.Is(err, authError{StatusCode: http.StatusBadRequest}) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"","error_description":""}`))
				return
			}
		}
		q := r.URL.Query()
		if v.Get("api-version") != q.Get("api-version") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if v.Get("resource") != q.Get("resource") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if v.Get("client_id") != q.Get("client_id") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if v.Get("mi_res_id") != q.Get("mi_res_id") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"ey12345","expires_in":3599}`))
	}))
	return ts
}

func setEnvVars(envs map[string]string) {
	os.Clearenv()
	for k, v := range envs {
		os.Setenv(k, v)
	}
}

func unsetEnvVars(envs map[string]string) {
	for k := range envs {
		os.Unsetenv(k)
	}
}

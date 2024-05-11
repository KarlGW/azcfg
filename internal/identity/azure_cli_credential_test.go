package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewAzureCLICredential(t *testing.T) {
	var tests = []struct {
		name    string
		input   []CredentialOption
		want    *AzureCLICredential
		wantErr error
	}{
		{
			name: "new azure cli credential",
			want: &AzureCLICredential{
				tokens: map[string]*auth.Token{},
			},
		},
		{
			name: "new azure cli credential - with options",
			input: []CredentialOption{
				func(o *CredentialOptions) {},
			},
			want: &AzureCLICredential{
				tokens: map[string]*auth.Token{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := NewAzureCLICredential(test.input...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(AzureCLICredential{}), cmpopts.IgnoreFields(AzureCLICredential{}, "mu")); diff != "" {
				t.Errorf("NewAzureCLICredential() = unexpected result, (-want, +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewAzureCLICredential() = unexpected error, (-want, +got)\n%s\n", diff)
			}
		})
	}
}

func TestAzureCLICredential_Token(t *testing.T) {
	var tests = []struct {
		name    string
		input   func() *AzureCLICredential
		want    auth.Token
		wantErr error
	}{
		{
			name: "get token",
			input: func() *AzureCLICredential {
				cred, _ := NewAzureCLICredential()
				return cred
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
		},
		{
			name: "get token from cache",
			input: func() *AzureCLICredential {
				cred, _ := NewAzureCLICredential()
				cred.tokens[_testScope] = &auth.Token{
					AccessToken: "ey54321",
					ExpiresOn:   time.Now().Add(time.Hour),
				}
				return cred
			},
			want: auth.Token{
				AccessToken: "ey54321",
			},
		},
		{
			name: "get token from cache (expired)",
			input: func() *AzureCLICredential {
				cred, _ := NewAzureCLICredential()
				cred.tokens[_testScope] = &auth.Token{
					AccessToken: "ey54321",
					ExpiresOn:   time.Now().Add(-3 * time.Hour),
				}
				return cred
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
		},
		{
			name: "error",
			input: func() *AzureCLICredential {
				cred, _ := NewAzureCLICredential()
				return cred
			},
			wantErr: errors.New("no token"),
		},
	}

	var oldCliToken = cliToken
	t.Cleanup(func() {
		cliToken = oldCliToken
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cliToken = func(_ string) (auth.Token, error) {
				if test.wantErr != nil {
					return auth.Token{}, test.wantErr
				}
				return auth.Token{
					AccessToken: "ey12345",
				}, nil
			}

			cred := test.input()
			got, gotErr := cred.Token(context.Background(), func(o *auth.TokenOptions) {
				o.Scope = _testScope
			})

			if diff := cmp.Diff(test.want, got, cmpopts.IgnoreFields(auth.Token{}, "ExpiresOn")); diff != "" {
				t.Errorf("Token() = unexpected result, (-want, +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Token() = unexpected error, (-want, +got)\n%s\n", diff)
			}
		})
	}
}

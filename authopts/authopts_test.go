package authopts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/KarlGW/azcfg"
	"github.com/KarlGW/azcfg/auth"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	_testScope = "https://management.azure.com/.default"
)

func TestWithTokenCredential(t *testing.T) {
	t.Run("TokenCredential", func(t *testing.T) {
		got := azcfg.Options{}
		WithTokenCredential(mockTokenCredential{})(&got)

		want := azcfg.Options{
			Credential: &credential{
				TokenCredential: mockTokenCredential{},
			},
		}

		if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(credential{}, mockTokenCredential{}, azcfg.Entra{}), cmpopts.IgnoreFields(azcfg.Entra{}, "PrivateKey")); diff != "" {
			t.Errorf("WithTokenCredential() = unexpected result (-want +got)\n%s\n", diff)
		}
	})
}

func TestCredential_Token(t *testing.T) {
	var tests = []struct {
		name    string
		input   func() *credential
		want    auth.Token
		wantErr error
	}{
		{
			name: "get token",
			input: func() *credential {
				return &credential{
					TokenCredential: mockTokenCredential{},
					tokens:          map[string]*auth.Token{},
				}
			},
			want: auth.Token{
				AccessToken: "ey12345",
				ExpiresOn:   _testNow,
			},
			wantErr: nil,
		},
		{
			name: "get token from cache",
			input: func() *credential {
				return &credential{
					TokenCredential: mockTokenCredential{},
					tokens: map[string]*auth.Token{
						_testScope: {
							AccessToken: "ey54321",
							ExpiresOn:   _testNow.Add(time.Hour),
						},
					},
				}
			},
			want: auth.Token{
				AccessToken: "ey54321",
			},
			wantErr: nil,
		},
		{
			name: "get token from cache (expired)",
			input: func() *credential {
				return &credential{
					TokenCredential: mockTokenCredential{},
					tokens: map[string]*auth.Token{
						_testScope: {
							AccessToken: "ey54321",
							ExpiresOn:   time.Now().Add(-3 * time.Hour),
						},
					},
				}
			},
			want: auth.Token{
				AccessToken: "ey12345",
			},
		},
		{
			name: "error",
			input: func() *credential {
				return &credential{TokenCredential: mockTokenCredential{err: errTest}}
			},
			want:    auth.Token{},
			wantErr: errTest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cred := test.input()
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

type mockTokenCredential struct {
	err error
}

func (c mockTokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if c.err != nil {
		return azcore.AccessToken{}, c.err
	}
	return azcore.AccessToken{
		Token:     "ey12345",
		ExpiresOn: _testNow,
	}, nil
}

var _testNow = time.Now()
var errTest = errors.New("error")

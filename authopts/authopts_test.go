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

func TestWithTokenCredential(t *testing.T) {
	t.Run("TokenCredential", func(t *testing.T) {
		got := azcfg.Options{}
		WithTokenCredential(mockTokenCredential{})(&got)

		want := azcfg.Options{
			Credential: &credential{
				TokenCredential: mockTokenCredential{},
			},
		}

		if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(credential{}, mockTokenCredential{})); diff != "" {
			t.Errorf("WithTokenCredential() = unexpected result (-want +got)\n%s\n", diff)
		}
	})
}

func TestCredential_Token(t *testing.T) {
	var tests = []struct {
		name    string
		input   mockTokenCredential
		want    auth.Token
		wantErr error
	}{
		{
			name:  "success",
			input: mockTokenCredential{},
			want: auth.Token{
				AccessToken: "ey12345",
				ExpiresOn:   _testNow,
			},
			wantErr: nil,
		},
		{
			name: "error",
			input: mockTokenCredential{
				err: errTest,
			},
			want:    auth.Token{},
			wantErr: errTest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cred := credential{TokenCredential: &test.input, tokens: map[auth.Scope]*auth.Token{}}
			got, gotErr := cred.Token(context.Background())

			if diff := cmp.Diff(test.want, got); diff != "" {
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

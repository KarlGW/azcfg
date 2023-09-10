package auth

import (
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
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
		{
			name: "ExpiresIn is int",
			input: authResult{
				AccessToken: "ey12345",
				ExpiresIn:   int(3599),
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

			if diff := cmp.Diff(test.want, got, cmpopts.EquateApproxTime(time.Millisecond)); diff != "" {
				t.Errorf("tokenFromAuthResult() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

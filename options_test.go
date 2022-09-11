package azcfg

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/go-cmp/cmp"
)

func TestSetCredential(t *testing.T) {
	SetCredential(mockCredential{})
	want := "token"
	token, _ := opts.Credential.GetToken(context.TODO(), policy.TokenRequestOptions{})
	got := token.Token

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	reset()
}

func TestVault(t *testing.T) {
	want := "testvault"
	SetVault(want)
	got := opts.Vault

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	reset()
}

func TestGetVaultFromEnvironment(t *testing.T) {
	var tests = []struct {
		name    string
		input   map[string]string
		want    string
		wantErr error
	}{
		{
			name:    "AZURE_KEY_VAULT",
			input:   map[string]string{"AZURE_KEY_VAULT": "vault-name"},
			want:    "vault-name",
			wantErr: nil,
		},
		{
			name:    "AZURE_KEY_VAULT_NAME",
			input:   map[string]string{"AZURE_KEY_VAULT_NAME": "vault-name"},
			want:    "vault-name",
			wantErr: nil,
		},
		{
			name:    "AZURE_KEYVAULT",
			input:   map[string]string{"AZURE_KEYVAULT": "vault-name"},
			want:    "vault-name",
			wantErr: nil,
		},
		{
			name:    "AZURE_KEYVAULT_NAME",
			input:   map[string]string{"AZURE_KEYVAULT_NAME": "vault-name"},
			want:    "vault-name",
			wantErr: nil,
		},
		{
			name:    "failure",
			input:   nil,
			want:    "",
			wantErr: errors.New("a Key Vault name must be setaaaa"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnv(test.input)
			got, err := getVaultFromEnvironment()
			unsetEnv(test.input)

			if test.wantErr == nil && err != nil {
				t.Errorf("should not return error: %v", err)
			}

			if !cmp.Equal(test.want, got) {
				t.Log(cmp.Diff(test.want, got))
				t.Errorf("results differ")
			}

			if test.wantErr != nil && err == nil {
				t.Errorf("should return error")
			}
		})
	}
}

func reset() {
	opts = &options{
		Credential: nil,
		Vault:      "",
	}
}

type mockCredential struct{}

func (c mockCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "token"}, nil
}

func setEnv(vars map[string]string) {
	for k, v := range vars {
		os.Setenv(k, v)
	}
}

func unsetEnv(vars map[string]string) {
	for k := range vars {
		os.Unsetenv(k)
	}
}

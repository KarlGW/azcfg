package azcfg

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVaultFromEnvironment(t *testing.T) {
	var tests = []struct {
		name    string
		input   map[string]string
		want    string
		wantErr error
	}{
		{
			name:    "AZCFG_AZURE_KEY_VAULT",
			input:   map[string]string{"AZCFG_AZURE_KEY_VAULT": "vault-name"},
			want:    "vault-name",
			wantErr: nil,
		},
		{
			name:    "AZCFG_AZURE_KEY_VAULT_NAME",
			input:   map[string]string{"AZCFG_AZURE_KEY_VAULT_NAME": "vault-name"},
			want:    "vault-name",
			wantErr: nil,
		},
		{
			name:    "AZCFG_AZURE_KEYVAULT",
			input:   map[string]string{"AZCFG_AZURE_KEYVAULT": "vault-name"},
			want:    "vault-name",
			wantErr: nil,
		},
		{
			name:    "AZCFG_AZURE_KEYVAULT_NAME",
			input:   map[string]string{"AZCFG_AZURE_KEYVAULT_NAME": "vault-name"},
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
			got, gotErr := vaultFromEnvironment()
			unsetEnv(test.input)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("vaultFromEnvironment() = unexpected result, (-want, +got)\n%s\n", diff)
			}

			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Unexpected result, should return error\n")
			}
		})
	}
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

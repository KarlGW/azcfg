package azcfg

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVaultFromEnvironment(t *testing.T) {
	var tests = []struct {
		name  string
		input map[string]string
		want  string
	}{
		{
			name:  "AZCFG_KEY_VAULT",
			input: map[string]string{"AZCFG_KEY_VAULT": "vault-name"},
			want:  "vault-name",
		},
		{
			name:  "AZCFG_KEY_VAULT_NAME",
			input: map[string]string{"AZCFG_KEY_VAULT_NAME": "vault-name"},
			want:  "vault-name",
		},
		{
			name:  "AZCFG_KEYVAULT",
			input: map[string]string{"AZCFG_KEYVAULT": "vault-name"},
			want:  "vault-name",
		},
		{
			name:  "AZCFG_KEYVAULT_NAME",
			input: map[string]string{"AZCFG_KEYVAULT_NAME": "vault-name"},
			want:  "vault-name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnv(test.input)
			got := vaultFromEnvironment()
			unsetEnv(test.input)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("vaultFromEnvironment() = unexpected result, (-want, +got)\n%s\n", diff)
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

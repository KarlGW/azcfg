package azcfg

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/go-cmp/cmp"
)

func TestSetOptions(t *testing.T) {
	var tests = []struct {
		name  string
		input *Options
		want  *options
	}{
		{
			name: "full",
			input: &Options{
				Secrets: &SecretsOptions{
					Vault: "vault-name",
				},
				AzureCredential: mockAzureCredential{},
				Concurrency:     20,
				Timeout:         time.Millisecond * 1000 * 20,
			},
			want: &options{
				secrets: &secrets{
					vault: "vault-name",
				},
				azureCredential: mockAzureCredential{},
				concurrency:     20,
				timeout:         time.Millisecond * 1000 * 20,
			},
		},
		{
			name: "partial",
			input: &Options{
				Secrets: &SecretsOptions{
					Vault: "vault-name",
				},
				AzureCredential: mockAzureCredential{},
			},
			want: &options{
				secrets: &secrets{
					vault: "vault-name",
				},
				azureCredential: mockAzureCredential{},
				concurrency:     defaultOpts.concurrency,
				timeout:         defaultOpts.timeout,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetOptions(test.input)

			if !cmp.Equal(test.want, opts, cmp.AllowUnexported(options{}, secrets{})) {
				t.Log(cmp.Diff(test.want, opts, cmp.AllowUnexported(options{}, secrets{})))
				t.Errorf("results differ")
			}

			resetOptions()
		})
	}
}

func TestSetSecretsClient(t *testing.T) {
	want := mockKeyVaultClient{}
	SetSecretsClient(mockKeyVaultClient{})
	got := opts.secrets.client

	if !cmp.Equal(want, got, cmp.AllowUnexported(mockKeyVaultClient{})) {
		t.Log(cmp.Diff(want, got, cmp.AllowUnexported(mockKeyVaultClient{})))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestSetSecretsVault(t *testing.T) {
	want := "testvault"
	SetSecretsVault(want)
	got := opts.secrets.vault

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestSetAzureCredential(t *testing.T) {
	SetAzureCredential(mockAzureCredential{})
	want := "token"
	token, _ := opts.azureCredential.GetToken(context.TODO(), policy.TokenRequestOptions{})
	got := token.Token

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestSetConcurrency(t *testing.T) {
	want := 20
	SetConcurrency(want)
	got := opts.concurrency

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestSetTimeout(t *testing.T) {
	want := time.Millisecond * 1000 * 20
	SetTimeout(want)
	got := opts.timeout

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestGetSecretsVaultFromEnvironment(t *testing.T) {
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
			got, err := getSecretsVaultFromEnvironment()
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

func resetOptions() {
	opts = &options{
		secrets: &secrets{
			vault: defaultOpts.secrets.vault,
		},
		azureCredential: defaultOpts.azureCredential,
		concurrency:     defaultOpts.concurrency,
		timeout:         defaultOpts.timeout,
	}
}

type mockAzureCredential struct{}

func (c mockAzureCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
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

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

func TestSetClientOptions(t *testing.T) {
	var tests = []struct {
		name  string
		input *ClientOptions
		want  *options
	}{
		{
			name: "full",
			input: &ClientOptions{
				Credential:  mockCredential{},
				Vault:       "vault-name",
				Concurrency: 20,
				Timeout:     time.Millisecond * 1000 * 20,
			},
			want: &options{
				client: client{
					credential:  mockCredential{},
					vault:       "vault-name",
					concurrency: 20,
					timeout:     time.Millisecond * 1000 * 20,
				},
			},
		},
		{
			name: "partial",
			input: &ClientOptions{
				Credential: mockCredential{},
				Vault:      "vault-name",
			},
			want: &options{
				client: client{
					credential:  mockCredential{},
					vault:       "vault-name",
					concurrency: defaultConcurrency,
					timeout:     defaultTimeout,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetClientOptions(test.input)

			if !cmp.Equal(test.want, opts, cmp.AllowUnexported(options{}, client{})) {
				t.Log(cmp.Diff(test.want, opts, cmp.AllowUnexported(options{}, client{})))
				t.Errorf("results differ")
			}

			resetOptions()
		})
	}
}

func TestSetCredential(t *testing.T) {
	SetCredential(mockCredential{})
	want := "token"
	token, _ := opts.client.credential.GetToken(context.TODO(), policy.TokenRequestOptions{})
	got := token.Token

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestSetVault(t *testing.T) {
	want := "testvault"
	SetVault(want)
	got := opts.client.vault

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestSetConcurrency(t *testing.T) {
	want := 20
	SetConcurrency(want)
	got := opts.client.concurrency

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
}

func TestSetTimeout(t *testing.T) {
	want := time.Millisecond * 1000 * 20
	SetTimeout(want)
	got := opts.client.timeout

	if !cmp.Equal(want, got) {
		t.Log(cmp.Diff(want, got))
		t.Errorf("results differ")
	}
	resetOptions()
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

func resetOptions() {
	opts = &options{
		client: client{
			credential:  defaultOpts.client.credential,
			vault:       defaultOpts.client.vault,
			concurrency: defaultOpts.client.concurrency,
			timeout:     defaultOpts.client.timeout,
		},
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

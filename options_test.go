package azcfg

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/KarlGW/azcfg/internal/keyvault"
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
				secrets: secrets{
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
				secrets: secrets{
					vault: "vault-name",
				},
				azureCredential: mockAzureCredential{},
				concurrency:     defaultConcurrency,
				timeout:         defaultTimeout,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetOptions(test.input)

			if diff := cmp.Diff(test.want, pkgOpts, cmp.AllowUnexported(options{}, secrets{})); diff != "" {
				t.Errorf("SetOptions(%+v) = unexpected result, (-want, +got)\n%s\n", test.input, diff)
			}
			resetOptions()
		})
	}
}

func TestSetSecretsClient(t *testing.T) {
	want := mockKeyVaultClient{}
	SetSecretsClient(mockKeyVaultClient{})
	got := pkgOpts.secrets.client

	if diff := cmp.Diff(want, got, cmp.AllowUnexported(mockKeyVaultClient{})); diff != "" {
		t.Errorf("SetSecretsClient(%+v) = unexpected result, (-want, +got)\n%s\n", mockKeyVaultClient{}, diff)
	}
	resetOptions()
}

func TestSetSecretsVault(t *testing.T) {
	want := "testvault"
	SetSecretsVault(want)
	got := pkgOpts.secrets.vault

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetSecretsVault(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
	}
	resetOptions()
}

func TestSetAzureCredential(t *testing.T) {
	SetAzureCredential(mockAzureCredential{})
	want := "token"
	token, _ := pkgOpts.azureCredential.GetToken(context.TODO(), policy.TokenRequestOptions{})
	got := token.Token

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetAzureCredential(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
	}
	resetOptions()
}

func TestSetConcurrency(t *testing.T) {
	want := 20
	SetConcurrency(want)
	got := pkgOpts.concurrency

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetConcurrency(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
	}
	resetOptions()
}

func TestSetTimeout(t *testing.T) {
	want := time.Millisecond * 1000 * 20
	SetTimeout(want)
	got := pkgOpts.timeout

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetTimeout(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
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
			got, gotErr := getSecretsVaultFromEnvironment()
			unsetEnv(test.input)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("getSecretsVaultFromEnvironment() = unexpected result, (-want, +got)\n%s\n", diff)
			}

			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Unexpected result, should return error\n")
			}
			resetOptions()
		})
	}
}

func TestSetChaining(t *testing.T) {
	want := &options{
		secrets: secrets{
			client: &mockKeyVaultClient{},
			vault:  "test-vault",
		},
		azureCredential: &mockAzureCredential{},
		concurrency:     20,
		timeout:         time.Millisecond * 1000 * 20,
	}

	got := SetSecretsClient(&mockKeyVaultClient{}).SetSecretsVault("test-vault").SetAzureCredential(&mockAzureCredential{}).SetConcurrency(20).SetTimeout(time.Millisecond * 1000 * 20).SetSecretsClient(&mockKeyVaultClient{})

	if diff := cmp.Diff(want, got, cmp.AllowUnexported(options{}, secrets{}, mockKeyVaultClient{}, mockAzureCredential{})); diff != "" {
		t.Errorf("Unexpected result, (-want, +got)\n%s\n", diff)
	}

	resetOptions()
}

func TestEvalOptions(t *testing.T) {
	var tests = []struct {
		name        string
		input       []Options
		want        *options
		wantPkgOpts *options
	}{
		{
			name:  "package options",
			input: []Options{},
			want: &options{
				secrets:     secrets{},
				concurrency: defaultConcurrency,
				timeout:     defaultTimeout,
			},
			wantPkgOpts: &options{
				secrets:     secrets{},
				concurrency: 10,
				timeout:     time.Millisecond * 1000 * 10,
			},
		},
		{
			name: "provided options (client)",
			input: []Options{
				{
					Secrets: &SecretsOptions{
						Client: mockKeyVaultClient{},
						Vault:  "vault-name",
					},
					Concurrency: 5,
					Timeout:     time.Second * 20,
				},
			},
			want: &options{
				secrets: secrets{
					client: mockKeyVaultClient{},
					vault:  "vault-name",
				},
				concurrency: 5,
				timeout:     time.Second * 20,
			},
			wantPkgOpts: &options{
				secrets:         secrets{},
				azureCredential: nil,
				concurrency:     10,
				timeout:         time.Millisecond * 1000 * 10,
			},
		},
		{
			name: "provided options (credential)",
			input: []Options{
				{
					Secrets: &SecretsOptions{
						Vault: "vault-name",
					},
					AzureCredential: &mockAzureCredential{},
					Concurrency:     5,
					Timeout:         time.Second * 20,
				},
			},
			want: &options{
				secrets: secrets{
					vault: "vault-name",
				},
				azureCredential: &mockAzureCredential{},
				concurrency:     5,
				timeout:         time.Second * 20,
			},
			wantPkgOpts: &options{
				secrets:         secrets{},
				azureCredential: nil,
				concurrency:     10,
				timeout:         time.Millisecond * 1000 * 10,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := evalOptions(test.input...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(options{}, secrets{}, mockKeyVaultClient{})); diff != "" {
				t.Errorf("evalOptions(%+v) = unexpected result, (-want, +got)\n%s\n", test.input, diff)
			}

			if diff := cmp.Diff(test.wantPkgOpts, pkgOpts, cmp.AllowUnexported(options{}, secrets{}, mockKeyVaultClient{})); diff != "" {
				t.Errorf("evalOptions(%+v) = unexpected result, (-want, +got)\n%s\n", test.input, diff)
			}

			resetOptions()
		})
	}
}

func TestEvalClient(t *testing.T) {
	var tests = []struct {
		name    string
		input   *options
		options evalClientOptions
		env     map[string]string
		want    SecretsClient
		wantErr error
	}{
		{
			name: "client is provided",
			input: &options{
				secrets: secrets{
					client: &mockKeyVaultClient{},
				},
			},
			options: evalClientOptions{},
			env:     nil,
			want:    &mockKeyVaultClient{},
			wantErr: nil,
		},
		{
			name: "credentials and vault are provided",
			input: &options{
				secrets: secrets{
					vault: "vault-name",
				},
				azureCredential: &mockAzureCredential{},
			},
			options: evalClientOptions{},
			env:     nil,
			want:    &mockKeyVaultClient{},
		},
		{
			name: "credentials provided (vault environment variable)",
			input: &options{
				secrets: secrets{},
			},
			options: evalClientOptions{},
			env: map[string]string{
				"AZURE_KEYVAULT_NAME": "vault-name",
			},
			want:    &mockKeyVaultClient{},
			wantErr: nil,
		},
		{
			name:    "Empty secrets",
			input:   &options{},
			options: evalClientOptions{},
			env: map[string]string{
				"AZURE_KEYVAULT_NAME": "vault-name",
			},
			want:    &mockKeyVaultClient{},
			wantErr: nil,
		},
		{
			name:    "nil options",
			input:   nil,
			options: evalClientOptions{},
			env: map[string]string{
				"AZURE_KEYVAULT_NAME": "vault-name",
			},
			want:    &mockKeyVaultClient{},
			wantErr: nil,
		},
		{
			name:    "credential error",
			input:   &options{},
			options: evalClientOptions{credentialErr: errors.New("error")},
			env:     nil,
			want:    nil,
			wantErr: errors.New("error"),
		},
		{
			name:    "vault name error",
			input:   &options{},
			options: evalClientOptions{},
			env:     nil,
			want:    nil,
			wantErr: errors.New("error"),
		},
		{
			name:    "secrets client error",
			input:   &options{},
			options: evalClientOptions{secretsClientErr: errors.New("error")},
			env: map[string]string{
				"AZURE_KEYVAULT_NAME": "vault-name",
			},
			want:    &mockKeyVaultClient{},
			wantErr: errors.New("error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnv(test.env)
			got, gotErr := evalClient(
				test.input,
				func() (azcore.TokenCredential, error) {
					return mockAzureCredential{}, test.options.credentialErr
				},
				func(vault string, cred azcore.TokenCredential, options *keyvault.ClientOptions) (SecretsClient, error) {
					return &mockKeyVaultClient{}, test.options.secretsClientErr
				},
			)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(mockAzureCredential{}, mockKeyVaultClient{})); diff != "" {
				t.Errorf("evalClient(%+v, fn, fn) = unexpected result, (-want, +got)\n%s\n", test.input, diff)
			}

			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Unexpected result, should return error\n")
			}
			resetOptions()
			unsetEnv(test.env)
		})
	}
}

type evalClientOptions struct {
	credentialErr    error
	secretsClientErr error
}

func resetOptions() {
	pkgOpts = &options{
		secrets:         secrets{},
		azureCredential: nil,
		concurrency:     defaultConcurrency,
		timeout:         defaultTimeout,
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

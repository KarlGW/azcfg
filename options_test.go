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
		want  *Parser
	}{
		{
			name: "full",
			input: &Options{
				Credential:  mockAzureCredential{},
				Vault:       "vault-name",
				Concurrency: 20,
				Timeout:     time.Millisecond * 1000 * 20,
			},
			want: &Parser{
				vault:       "vault-name",
				credential:  mockAzureCredential{},
				concurrency: 20,
				timeout:     time.Millisecond * 1000 * 20,
			},
		},
		{
			name: "partial",
			input: &Options{
				Credential: mockAzureCredential{},
				Vault:      "vault-name",
			},
			want: &Parser{
				vault:       "vault-name",
				credential:  mockAzureCredential{},
				concurrency: defaultConcurrency,
				timeout:     defaultTimeout,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetOptions(test.input)

			if diff := cmp.Diff(test.want, parser, cmp.AllowUnexported(Parser{})); diff != "" {
				t.Errorf("SetOptions(%+v) = unexpected result, (-want, +got)\n%s\n", test.input, diff)
			}
			resetOptions()
		})
	}
}

func TestSetClient(t *testing.T) {
	want := mockKeyVaultClient{}
	SetClient(mockKeyVaultClient{})
	got := parser.client

	if diff := cmp.Diff(want, got, cmp.AllowUnexported(mockKeyVaultClient{})); diff != "" {
		t.Errorf("SetClient(%+v) = unexpected result, (-want, +got)\n%s\n", mockKeyVaultClient{}, diff)
	}
	resetOptions()
}

func TestVault(t *testing.T) {
	want := "testvault"
	SetVault(want)
	got := parser.vault

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetVault(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
	}
	resetOptions()
}

func TestSetCredential(t *testing.T) {
	SetCredential(mockAzureCredential{})
	want := "token"
	token, _ := parser.credential.GetToken(context.TODO(), policy.TokenRequestOptions{})
	got := token.Token

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetCredential(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
	}
	resetOptions()
}

func TestSetConcurrency(t *testing.T) {
	want := 20
	SetConcurrency(want)
	got := parser.concurrency

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetConcurrency(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
	}
	resetOptions()
}

func TestSetTimeout(t *testing.T) {
	want := time.Millisecond * 1000 * 20
	SetTimeout(want)
	got := parser.timeout

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SetTimeout(%q) = unexpected result, (-want, +got)\n%s\n", want, diff)
	}
	resetOptions()
}

func TestVaultFromEnvironment(t *testing.T) {
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
			got, gotErr := vaultFromEnvironment()
			unsetEnv(test.input)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("vaultFromEnvironment() = unexpected result, (-want, +got)\n%s\n", diff)
			}

			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Unexpected result, should return error\n")
			}
			resetOptions()
		})
	}
}

func TestSetChaining(t *testing.T) {
	want := &Parser{
		client:      &mockKeyVaultClient{},
		credential:  &mockAzureCredential{},
		vault:       "test-vault",
		concurrency: 20,
		timeout:     time.Millisecond * 1000 * 20,
	}

	got := SetClient(&mockKeyVaultClient{}).SetVault("test-vault").SetCredential(&mockAzureCredential{}).SetConcurrency(20).SetTimeout(time.Millisecond * 1000 * 20).SetClient(&mockKeyVaultClient{})

	if diff := cmp.Diff(want, got, cmp.AllowUnexported(Parser{}, mockKeyVaultClient{}, mockAzureCredential{})); diff != "" {
		t.Errorf("Unexpected result, (-want, +got)\n%s\n", diff)
	}

	resetOptions()
}

func TestEvalOptions(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			parser  *Parser
			options []Options
		}
		want *Parser
	}{
		{
			name: "package options",
			input: struct {
				parser  *Parser
				options []Options
			}{
				parser:  &Parser{},
				options: []Options{},
			},
			want: &Parser{},
		},
		{
			name: "provided options (client)",
			input: struct {
				parser  *Parser
				options []Options
			}{
				parser: &Parser{},
				options: []Options{
					{
						Client:      mockKeyVaultClient{},
						Vault:       "vault-name",
						Concurrency: 5,
						Timeout:     time.Second * 20,
					},
				},
			},
			want: &Parser{
				client:      mockKeyVaultClient{},
				vault:       "vault-name",
				concurrency: 5,
				timeout:     time.Second * 20,
			},
		},
		{
			name: "provided options (credential)",
			input: struct {
				parser  *Parser
				options []Options
			}{
				parser: &Parser{},
				options: []Options{
					{
						Credential:  &mockAzureCredential{},
						Vault:       "vault-name",
						Concurrency: 5,
						Timeout:     time.Second * 20,
					},
				},
			},
			want: &Parser{
				credential:  &mockAzureCredential{},
				vault:       "vault-name",
				concurrency: 5,
				timeout:     time.Second * 20,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := evalOptions(test.input.parser, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Parser{}, mockKeyVaultClient{})); diff != "" {
				t.Errorf("evalOptions(%+v) = unexpected result, (-want, +got)\n%s\n", test.input, diff)
			}

			resetOptions()
		})
	}
}

func TestEvalClient(t *testing.T) {
	var tests = []struct {
		name    string
		input   *Parser
		options evalClientOptions
		env     map[string]string
		want    *Parser
		wantErr error
	}{
		{
			name: "client is provided",
			input: &Parser{
				client: &mockKeyVaultClient{},
			},
			options: evalClientOptions{},
			env:     nil,
			want: &Parser{
				client: &mockKeyVaultClient{},
			},
			wantErr: nil,
		},
		{
			name: "credentials and vault are provided",
			input: &Parser{
				credential: &mockAzureCredential{},
				vault:      "vault-name",
			},
			options: evalClientOptions{},
			env:     nil,
			want: &Parser{
				client:     &mockKeyVaultClient{},
				credential: &mockAzureCredential{},
				vault:      "vault-name",
			},
		},
		{
			name:    "credentials provided (vault environment variable)",
			input:   &Parser{},
			options: evalClientOptions{},
			env: map[string]string{
				"AZURE_KEYVAULT_NAME": "vault-name",
			},
			want: &Parser{
				client:     &mockKeyVaultClient{},
				credential: &mockAzureCredential{},
				vault:      "vault-name",
			},
			wantErr: nil,
		},
		{
			name:    "nil parser",
			input:   nil,
			options: evalClientOptions{},
			env: map[string]string{
				"AZURE_KEYVAULT_NAME": "vault-name",
			},
			want:    nil,
			wantErr: errors.New("a *Parser must be provided"),
		},
		{
			name:    "credential error",
			input:   &Parser{},
			options: evalClientOptions{credentialErr: errors.New("error")},
			env:     nil,
			want: &Parser{
				credential: &mockAzureCredential{},
			},
			wantErr: errors.New("error"),
		},
		{
			name:    "vault name error",
			input:   &Parser{},
			options: evalClientOptions{},
			env:     nil,
			want: &Parser{
				credential: &mockAzureCredential{},
			},
			wantErr: errors.New("error"),
		},
		{
			name:    "secrets client error",
			input:   &Parser{},
			options: evalClientOptions{ClientErr: errors.New("error")},
			env: map[string]string{
				"AZURE_KEYVAULT_NAME": "vault-name",
			},
			want: &Parser{
				credential: &mockAzureCredential{},
				vault:      "vault-name",
			},
			wantErr: errors.New("error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnv(test.env)
			got, gotErr := evalClient(
				test.input,
				func() (azcore.TokenCredential, error) {
					return &mockAzureCredential{}, test.options.credentialErr
				},
				func(vault string, cred azcore.TokenCredential, options *keyvault.ClientOptions) (Client, error) {
					return &mockKeyVaultClient{}, test.options.ClientErr
				},
			)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Parser{}, mockAzureCredential{}, mockKeyVaultClient{})); diff != "" {
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
	credentialErr error
	ClientErr     error
}

func resetOptions() {
	parser = &Parser{
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
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

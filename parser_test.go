package azcfg

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/identity"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/stub"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewParser(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			options []Option
			envs    map[string]string
		}
		want    *parser
		wantErr error
	}{
		{
			name: "defaults (and settings from environment)",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					"AZCFG_KEYVAULT_NAME": "vault",
					"AZCFG_TENANT_ID":     "1111",
					"AZCFG_CLIENT_ID":     "2222",
					"AZCFG_CLIENT_SECRET": "3333",
				},
			},
			want: &parser{
				cl: &secret.Client{},
				cred: mockCredential{
					t: "sp",
				},
				timeout:     time.Second * 10,
				concurrency: 10,
				vault:       "vault",
			},
		},
		{
			name: "with options",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				options: []Option{
					WithConcurrency(20),
					WithTimeout(time.Second * 10),
					WithClientSecretCredential("1111", "2222", "3333"),
					WithVault("vault1"),
				},
			},
			want: &parser{
				cl: &secret.Client{},
				cred: mockCredential{
					t: "sp",
				},
				timeout:     time.Second * 10,
				concurrency: 20,
				vault:       "vault1",
			},
		},
		{
			name: "error setting up credential",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					"AZCFG_KEYVAULT_NAME": "vault",
					"AZCFG_TENANT_ID":     "1111",
					"AZCFG_CLIENT_ID":     "2222",
					"AZCFG_CLIENT_SECRET": "3333",
				},
			},
			want:    nil,
			wantErr: identity.ErrInvalidClientID,
		},
		{
			name: "error vault not set",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					"AZCFG_TENANT_ID":     "1111",
					"AZCFG_CLIENT_ID":     "2222",
					"AZCFG_CLIENT_SECRET": "3333",
				},
			},
			want:    nil,
			wantErr: ErrVaultNotSet,
		},
		{
			name: "secret client provided",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				options: []Option{
					WithSecretClient(stub.NewSecretClient(nil, nil)),
				},
			},
			want: &parser{
				cl:          stub.SecretClient{},
				cred:        nil,
				timeout:     time.Second * 10,
				concurrency: 10,
				vault:       "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newClientCredential = func(tenantID, clientID, clientSecret string) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "sp",
				}, nil
			}
			newManagedIdentityCredential = func(clientID string) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "mi",
				}, nil
			}

			setEnvVars(test.input.envs)
			defer unsetEnvVars(test.input.envs)

			got, gotErr := NewParser(test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(parser{}, mockCredential{}), cmpopts.IgnoreUnexported(secret.Client{}, stub.SecretClient{})); diff != "" {
				t.Errorf("NewParser() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewParser() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	var tests = []struct {
		name  string
		input Option
		want  Options
	}{
		{
			name:  "WithCredential()",
			input: WithCredential(mockCredential{}),
			want: Options{
				Credential: mockCredential{},
			},
		},
		{
			name:  "WithVault()",
			input: WithVault("vault"),
			want: Options{
				Vault: "vault",
			},
		},
		{
			name:  "WithConcurrency()",
			input: WithConcurrency(5),
			want: Options{
				Concurrency: 5,
			},
		},
		{
			name:  "WithTimeout()",
			input: WithTimeout(time.Second * 5),
			want: Options{
				Timeout: time.Second * 5,
			},
		},
		{
			name:  "WithClientSecretCredential()",
			input: WithClientSecretCredential("1111", "2222", "3333"),
			want: Options{
				TenantID:     "1111",
				ClientID:     "2222",
				ClientSecret: "3333",
			},
		},
		{
			name:  "WithManagedIdentity()",
			input: WithManagedIdentity("2222"),
			want: Options{
				ClientID:           "2222",
				UseManagedIdentity: true,
			},
		},
	}

	for _, test := range tests {
		got := Options{}
		test.input(&got)

		if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(mockCredential{})); diff != "" {
			t.Errorf("%s = unexpected result (-want +got)\n%s\n", test.name, diff)
		}
	}
}

func TestSetupCredential(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			options Options
			envs    map[string]string
		}
		want    auth.Credential
		wantErr error
	}{
		{
			name: "credential settings from environment (client credential)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				envs: map[string]string{
					"AZCFG_TENANT_ID":     "1111",
					"AZCFG_CLIENT_ID":     "2222",
					"AZCFG_CLIENT_SECRET": "3333",
				},
			},
			want: mockCredential{
				t: "sp",
			},
		},
		{
			name: "credential settings from envionment (managed identity)",
			input: struct {
				options Options
				envs    map[string]string
			}{},
			want: mockCredential{
				t: "mi",
			},
		},
		{
			name: "credential settings from options (client credential)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				options: Options{
					TenantID:     "1111",
					ClientID:     "2222",
					ClientSecret: "3333",
				},
			},
			want: mockCredential{
				t: "sp",
			},
		},
		{
			name: "credential settings from options (managed identity)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				options: Options{UseManagedIdentity: true},
			},
			want: mockCredential{
				t: "mi",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newClientCredential = func(tenantID, clientID, clientSecret string) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "sp",
				}, nil
			}
			newManagedIdentityCredential = func(clientID string) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "mi",
				}, nil
			}

			setEnvVars(test.input.envs)
			defer unsetEnvVars(test.input.envs)

			got, gotErr := setupCredential(test.input.options)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(mockCredential{})); diff != "" {
				t.Errorf("setupCredential() = unexpected (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("setupCredential() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestSetupVault(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			vault string
			envs  map[string]string
		}
		want string
	}{
		{
			name: "vault from environment",
			input: struct {
				vault string
				envs  map[string]string
			}{
				envs: map[string]string{
					"AZCFG_KEYVAULT_NAME": "vault",
				},
			},
			want: "vault",
		},
		{
			name: "name from options",
			input: struct {
				vault string
				envs  map[string]string
			}{
				vault: "vault",
			},
			want: "vault",
		},
		{
			name: "name from options, override environment",
			input: struct {
				vault string
				envs  map[string]string
			}{
				vault: "vault1",
				envs: map[string]string{
					"AZCFG_KEYVAULT_NAME": "vault2",
				},
			},
			want: "vault1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setEnvVars(test.input.envs)
			defer unsetEnvVars(test.input.envs)

			got := setupVault(test.input.vault)

			if test.want != got {
				t.Errorf("setupVault() = unexpected result, want: %s, got: %s\n", test.want, got)
			}
		})
	}
}

func setEnvVars(envs map[string]string) {
	os.Clearenv()
	for k, v := range envs {
		os.Setenv(k, v)
	}
}

func unsetEnvVars(envs map[string]string) {
	for k := range envs {
		os.Unsetenv(k)
	}
}

type mockCredential struct {
	t string
}

func (c mockCredential) Token(ctx context.Context) (auth.Token, error) {
	return auth.Token{}, nil
}

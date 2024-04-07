package azcfg

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/internal/identity"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
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
			name: "setting up secret and setting client",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgKeyVaultName:         "vault",
					azcfgAppConfigurationName: "appconfig",
					azcfgTenantID:             "1111",
					azcfgClientID:             "2222",
					azcfgClientSecret:         "3333",
				},
			},
			want: &parser{
				secretClient:  &secret.Client{},
				settingClient: &setting.Client{},
				cred: mockCredential{
					t: "client-secret-credential",
				},
				timeout:     time.Second * 10,
				concurrency: 10,
			},
		},
		{
			name: "setting up secret client",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgKeyVaultName: "vault",
					azcfgTenantID:     "1111",
					azcfgClientID:     "2222",
					azcfgClientSecret: "3333",
				},
			},
			want: &parser{
				secretClient: &secret.Client{},
				cred: mockCredential{
					t: "client-secret-credential",
				},
				timeout:     time.Second * 10,
				concurrency: 10,
			},
		},
		{
			name: "setting up setting client",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgAppConfigurationName: "appconfig",
					azcfgTenantID:             "1111",
					azcfgClientID:             "2222",
					azcfgClientSecret:         "3333",
				},
			},
			want: &parser{
				settingClient: &setting.Client{},
				cred: mockCredential{
					t: "client-secret-credential",
				},
				timeout:     time.Second * 10,
				concurrency: 10,
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
					WithKeyVault("vault1"),
					WithAppConfiguration("appconfig"),
				},
			},
			want: &parser{
				secretClient:  &secret.Client{},
				settingClient: &setting.Client{},
				cred: mockCredential{
					t: "client-secret-credential",
				},
				timeout:     time.Second * 10,
				concurrency: 20,
			},
		},
		{
			name: "error setting up credential",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgKeyVaultName:         "vault",
					azcfgAppConfigurationName: "appconfig",
					azcfgTenantID:             "1111",
					azcfgClientID:             "2222",
					azcfgClientSecret:         "3333",
				},
			},
			want:    nil,
			wantErr: identity.ErrInvalidClientID,
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
				secretClient:  stub.SecretClient{},
				settingClient: nil,
				cred:          nil,
				timeout:       time.Second * 10,
				concurrency:   10,
			},
		},
		{
			name: "setting client provided",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				options: []Option{
					WithSettingClient(stub.NewSettingClient(nil, nil)),
				},
			},
			want: &parser{
				secretClient:  nil,
				settingClient: stub.SettingClient{},
				cred:          nil,
				timeout:       time.Second * 10,
				concurrency:   10,
			},
		},
		{
			name: "secret and setting client provided",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				options: []Option{
					WithSecretClient(stub.NewSecretClient(nil, nil)),
					WithSettingClient(stub.NewSettingClient(nil, nil)),
				},
			},
			want: &parser{
				secretClient:  stub.SecretClient{},
				settingClient: stub.SettingClient{},
				cred:          nil,
				timeout:       time.Second * 10,
				concurrency:   10,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			os.Clearenv()

			newClientSecretCredential = func(tenantID, clientID, clientSecret string, options ...identity.CredentialOption) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "client-secret-credential",
				}, nil
			}
			newClientCertificateCredential = func(tenantID, clientID string, certificate []*x509.Certificate, key *rsa.PrivateKey, options ...identity.CredentialOption) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "client-certificate-credential",
				}, nil
			}
			newManagedIdentityCredential = func(clientID string, options ...identity.CredentialOption) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "managed-identity",
				}, nil
			}

			for k, v := range test.input.envs {
				t.Setenv(k, v)
			}

			got, gotErr := NewParser(test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(parser{}, mockCredential{}), cmpopts.IgnoreUnexported(secret.Client{}, stub.SecretClient{}, setting.Client{}, stub.SettingClient{})); diff != "" {
				t.Errorf("NewParser() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewParser() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
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
			name: "credential settings from environment (client secret credential)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgTenantID:     "1111",
					azcfgClientID:     "2222",
					azcfgClientSecret: "3333",
				},
			},
			want: mockCredential{
				t: "client-secret-credential",
			},
		},
		{
			name: "credential settings from environment (client certificate credential from base64)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgTenantID:          "1111",
					azcfgClientID:          "2222",
					azcfgClientCertificate: "certificate",
				},
			},
			want: mockCredential{
				t: "client-certificate-credential",
			},
		},
		{
			name: "credential settings from environment (client certificate credential from file)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgTenantID:              "1111",
					azcfgClientID:              "2222",
					azcfgClientCertificatePath: "certificate",
				},
			},
			want: mockCredential{
				t: "client-certificate-credential",
			},
		},
		{
			name: "credential settings from environment (managed identity)",
			input: struct {
				options Options
				envs    map[string]string
			}{},
			want: mockCredential{
				t: "managed-identity",
			},
		},
		{
			name: "credential settings from options (provided credential)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				options: Options{
					Credential: mockCredential{
						t: "custom",
					},
				},
			},
			want: mockCredential{
				t: "custom",
			},
		},
		{
			name: "credential settings from options (client secret credential)",
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
				t: "client-secret-credential",
			},
		},
		{
			name: "credential settings from options (client certificate credential)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				options: Options{
					TenantID:     "1111",
					ClientID:     "2222",
					Certificates: []*x509.Certificate{{}},
					PrivateKey:   &rsa.PrivateKey{},
				},
			},
			want: mockCredential{
				t: "client-certificate-credential",
			},
		},
		{
			name: "credential settings from options (managed identity)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				options: Options{ManagedIdentity: true},
			},
			want: mockCredential{
				t: "managed-identity",
			},
		},
		{
			name: "error setting up client certificate credential",
			input: struct {
				options Options
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgTenantID:              "1111",
					azcfgClientID:              "2222",
					azcfgClientCertificatePath: "certificate",
				},
			},
			wantErr: errors.New("invalid path"),
		},
		{
			name: "error missing client ID",
			input: struct {
				options Options
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgTenantID: "1111",
				},
			},
			wantErr: ErrMissingClientID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			os.Clearenv()

			newClientSecretCredential = func(_, _, _ string, _ ...identity.CredentialOption) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "client-secret-credential",
				}, nil
			}
			newClientCertificateCredential = func(_, _ string, _ []*x509.Certificate, _ *rsa.PrivateKey, _ ...identity.CredentialOption) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "client-certificate-credential",
				}, nil
			}
			newManagedIdentityCredential = func(_ string, _ ...identity.CredentialOption) (auth.Credential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return mockCredential{
					t: "managed-identity",
				}, nil
			}
			certificateAndKey = func(_, _ string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
				if test.wantErr != nil {
					return nil, nil, test.wantErr
				}
				return []*x509.Certificate{{}}, &rsa.PrivateKey{}, nil
			}

			for k, v := range test.input.envs {
				t.Setenv(k, v)
			}

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

func TestSetupKeyVault(t *testing.T) {
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
					azcfgKeyVaultName: "vault",
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
					azcfgKeyVaultName: "vault2",
				},
			},
			want: "vault1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range test.input.envs {
				t.Setenv(k, v)
			}

			got := setupKeyVault(test.input.vault)

			if test.want != got {
				t.Errorf("setupKeyVault() = unexpected result, want: %s, got: %s\n", test.want, got)
			}
		})
	}
}

func TestSetupAppConfiguration(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			appConfig string
			label     string
			envs      map[string]string
		}
		wantAppConfig string
		wantLabel     string
	}{
		{
			name: "App Configuration from environment",
			input: struct {
				appConfig string
				label     string
				envs      map[string]string
			}{
				envs: map[string]string{
					azcfgAppConfigurationName: "appconfig",
				},
			},
			wantAppConfig: "appconfig",
		},
		{
			name: "App Confiruation from options",
			input: struct {
				appConfig string
				label     string
				envs      map[string]string
			}{
				appConfig: "appconfig",
			},
			wantAppConfig: "appconfig",
		},
		{
			name: "App Configuration from option, override environment",
			input: struct {
				appConfig string
				label     string
				envs      map[string]string
			}{
				appConfig: "appconfig1",
				envs: map[string]string{
					azcfgAppConfigurationName: "appconfig2",
				},
			},
			wantAppConfig: "appconfig1",
		},
		{
			name: "App Configuration label from environment",
			input: struct {
				appConfig string
				label     string
				envs      map[string]string
			}{
				envs: map[string]string{
					azcfgAppConfigurationLabel: "label",
				},
			},
			wantLabel: "label",
		},
		{
			name: "App Configuration label from options",
			input: struct {
				appConfig string
				label     string
				envs      map[string]string
			}{
				label: "label",
			},
			wantLabel: "label",
		},
		{
			name: "App Configuration label from options, override environment",
			input: struct {
				appConfig string
				label     string
				envs      map[string]string
			}{
				label: "label1",
				envs: map[string]string{
					azcfgAppConfigurationLabel: "label2",
				},
			},
			wantLabel: "label1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			os.Clearenv()

			for k, v := range test.input.envs {
				t.Setenv(k, v)
			}

			gotAppConfig, gotLabel := setupAppConfiguration(test.input.appConfig, test.input.label)

			if test.wantAppConfig != gotAppConfig {
				t.Errorf("setupAppConfiguration() = unexpected result, want: %s, got: %s\n", test.wantAppConfig, gotAppConfig)
			}

			if test.wantLabel != gotLabel {
				t.Errorf("setupAppConfiguration() = unexpected result, want: %s, got: %s\n", test.wantLabel, gotLabel)
			}
		})
	}
}

func TestCoalesceString(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			x, y string
		}
		want string
	}{
		{
			name: "x is not empty",
			input: struct {
				x, y string
			}{
				x: "x",
				y: "y",
			},
			want: "x",
		},
		{
			name: "x is empty",
			input: struct {
				x, y string
			}{
				x: "",
				y: "y",
			},
			want: "y",
		},
		{
			name: "x and y are empty",
			input: struct {
				x, y string
			}{
				x: "",
				y: "",
			},
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := coalesceString(test.input.x, test.input.y)

			if test.want != got {
				t.Errorf("coalesceString() = unexpected result, want: %s, got: %s\n", test.want, got)
			}
		})
	}
}

type mockCredential struct {
	t string
}

func (c mockCredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	return auth.Token{}, nil
}

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
				cred:          &identity.ClientCredential{},
				timeout:       time.Second * 10,
				concurrency:   10,
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
				cred:         &identity.ClientCredential{},
				timeout:      time.Second * 10,
				concurrency:  10,
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
				cred:          &identity.ClientCredential{},
				timeout:       time.Second * 10,
				concurrency:   10,
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
				cred:          &identity.ClientCredential{},
				timeout:       time.Second * 10,
				concurrency:   20,
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

			newClientSecretCredential = func(tenantID, clientID, clientSecret string, options ...identity.CredentialOption) (*identity.ClientCredential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return &identity.ClientCredential{}, nil
			}
			newClientCertificateCredential = func(tenantID, clientID string, certificate []*x509.Certificate, key *rsa.PrivateKey, options ...identity.CredentialOption) (*identity.ClientCredential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return &identity.ClientCredential{}, nil
			}
			newManagedIdentityCredential = func(clientID string, options ...identity.CredentialOption) (*identity.ManagedIdentityCredential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return &identity.ManagedIdentityCredential{}, nil
			}

			for k, v := range test.input.envs {
				t.Setenv(k, v)
			}

			got, gotErr := NewParser(test.input.options...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(parser{}, mockCredential{}), cmpopts.IgnoreUnexported(secret.Client{}, stub.SecretClient{}, setting.Client{}, stub.SettingClient{}, identity.ClientCredential{}, identity.ManagedIdentityCredential{})); diff != "" {
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
			want: &identity.ClientCredential{},
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
			want: &identity.ClientCredential{},
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
			want: &identity.ClientCredential{},
		},
		{
			name: "credential settings from environment (managed identity)",
			input: struct {
				options Options
				envs    map[string]string
			}{},
			want: &identity.ManagedIdentityCredential{},
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
			want: &identity.ClientCredential{},
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
			want: &identity.ClientCredential{},
		},
		{
			name: "credential settings from options (managed identity)",
			input: struct {
				options Options
				envs    map[string]string
			}{
				options: Options{ManagedIdentity: true},
			},
			want: &identity.ManagedIdentityCredential{},
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

			newClientSecretCredential = func(_, _, _ string, _ ...identity.CredentialOption) (*identity.ClientCredential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return &identity.ClientCredential{}, nil
			}
			newClientCertificateCredential = func(_, _ string, _ []*x509.Certificate, _ *rsa.PrivateKey, _ ...identity.CredentialOption) (*identity.ClientCredential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return &identity.ClientCredential{}, nil
			}
			newManagedIdentityCredential = func(_ string, _ ...identity.CredentialOption) (*identity.ManagedIdentityCredential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return &identity.ManagedIdentityCredential{}, nil
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

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(mockCredential{}), cmpopts.IgnoreUnexported(identity.ClientCredential{}, identity.ManagedIdentityCredential{})); diff != "" {
				t.Errorf("setupCredential() = unexpected (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("setupCredential() = unexpected error (-want +got)\n%s\n", diff)
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

func TestCoalesceBool(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			x, y bool
		}
		want bool
	}{
		{
			name: "x is true",
			input: struct {
				x, y bool
			}{
				x: true,
				y: false,
			},
			want: true,
		},
		{
			name: "x is false",
			input: struct {
				x, y bool
			}{
				x: false,
				y: true,
			},
			want: true,
		},
		{
			name: "x and y are false",
			input: struct {
				x, y bool
			}{
				x: false,
				y: false,
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := coalesceBool(test.input.x, test.input.y)

			if test.want != got {
				t.Errorf("coalesceBool() = unexpected result, want: %t, got: %t\n", test.want, got)
			}
		})
	}
}

func TestCoalesceMap(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			x, y map[string]string
		}
		want map[string]string
	}{
		{
			name: "x is not empty",
			input: struct {
				x, y map[string]string
			}{
				x: map[string]string{
					"setting1": "prod",
				},
			},
			want: map[string]string{
				"setting1": "prod",
			},
		},
		{
			name: "x is empty",
			input: struct {
				x, y map[string]string
			}{
				x: nil,
				y: map[string]string{
					"setting1": "prod",
				},
			},
			want: map[string]string{
				"setting1": "prod",
			},
		},
		{
			name: "x and y are empty",
			input: struct {
				x, y map[string]string
			}{
				x: nil,
				y: nil,
			},
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := coalesceMap(test.input.x, test.input.y)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("coalesceMap() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestParseLabels(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name: "empty string",
			want: nil,
		},
		{
			name:  "with labels",
			input: "setting1=prod,setting2=test",
			want: map[string]string{
				"setting1": "prod",
				"setting2": "test",
			},
		},
		{
			name:  "with labels (spaces in string)",
			input: "setting1 = prod, setting2 = test",
			want: map[string]string{
				"setting1": "prod",
				"setting2": "test",
			},
		},
		{
			name:  "with malformed label",
			input: "setting1",
			want:  nil,
		},
		{
			name:  "with malformed second label",
			input: "settign1=prod,setting2",
			want: map[string]string{
				"settign1": "prod",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseLabels(test.input)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("parseLabels() = unexpected result (-want +got)\n%s\n", diff)
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

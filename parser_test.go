package azcfg

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/auth"
	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/internal/identity"
	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
	"github.com/KarlGW/azcfg/internal/testutils"
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
			name: "setting up secret and setting client (environment)",
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
				timeout:       time.Second * 10,
			},
		},
		{
			name: "setting up secret client (environment)",
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
				timeout:      time.Second * 10,
			},
		},
		{
			name: "setting up setting client (environment)",
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
				timeout:       time.Second * 10,
			},
		},
		{
			name: "setting up setting client with access key (environment)",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgAppConfigurationName:            "appconfig",
					azcfgAppConfigurationAccessKeyID:     "id",
					azcfgAppConfigurationAccessKeySecret: "secret",
				},
			},
			want: &parser{
				settingClient: &setting.Client{},
				timeout:       time.Second * 10,
			},
		},
		{
			name: "setting up setting client with access key, overriding provided credential (environment)",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				options: []Option{
					WithCredential(&mockCredential{}),
				},
				envs: map[string]string{
					azcfgAppConfigurationName:            "appconfig",
					azcfgAppConfigurationAccessKeyID:     "id",
					azcfgAppConfigurationAccessKeySecret: "secret",
				},
			},
			want: &parser{
				settingClient: &setting.Client{},
				timeout:       time.Second * 10,
			},
		},
		{
			name: "setting up setting client with connection string (environment)",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				envs: map[string]string{
					azcfgAppConfigurationName:             "appconfig",
					azcfgAppConfigurationConnectionString: "Endpoint=https://config.azconfig.io;Id=id;Secret=secret",
				},
			},
			want: &parser{
				settingClient: &setting.Client{},
				timeout:       time.Second * 10,
			},
		},
		{
			name: "setting up setting client with connection string, override provided credential (environment)",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				options: []Option{
					WithCredential(&mockCredential{}),
				},
				envs: map[string]string{
					azcfgAppConfigurationName:             "appconfig",
					azcfgAppConfigurationConnectionString: "Endpoint=https://config.azconfig.io;Id=id;Secret=secret",
				},
			},
			want: &parser{
				settingClient: &setting.Client{},
				timeout:       time.Second * 10,
			},
		},
		{
			name: "with options",
			input: struct {
				options []Option
				envs    map[string]string
			}{
				options: []Option{
					WithConcurrency(30),
					WithTimeout(time.Second * 10),
					WithClientSecretCredential("1111", "2222", "3333"),
					WithKeyVault("vault1"),
					WithAppConfiguration("appconfig"),
				},
			},
			want: &parser{
				secretClient:  &secret.Client{},
				settingClient: &setting.Client{},
				timeout:       time.Second * 10,
			},
		},
		{
			name: "error setting up credential for secrets",
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
			want:    nil,
			wantErr: identity.ErrInvalidClientID,
		},
		{
			name: "error setting up credential for settings",
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
				timeout:       time.Second * 10,
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
				timeout:       time.Second * 10,
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
				timeout:       time.Second * 10,
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

func TestParser_Parse(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			s          Struct
			options    []Option
			secrets    map[string]string
			secretErr  error
			settings   map[string]string
			settingErr error
		}
		want    Struct
		wantErr error
	}{
		{
			name: "parse secrets and settings",
			input: struct {
				s          Struct
				options    []Option
				secrets    map[string]string
				secretErr  error
				settings   map[string]string
				settingErr error
			}{
				s: Struct{},
				secrets: map[string]string{
					"string": "new string",
				},
				settings: map[string]string{
					"string-setting": "new string setting",
				},
			},
			want: Struct{
				String:        "new string",
				StringSetting: "new string setting",
			},
		},
		{
			name: "parse secrets and settings with context",
			input: struct {
				s          Struct
				options    []Option
				secrets    map[string]string
				secretErr  error
				settings   map[string]string
				settingErr error
			}{
				s: Struct{},
				secrets: map[string]string{
					"string": "new string",
				},
				settings: map[string]string{
					"string-setting": "new string setting",
				},
				options: []Option{
					WithContext(context.Background()),
				},
			},
			want: Struct{
				String:        "new string",
				StringSetting: "new string setting",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := &parser{
				secretClient:  stub.NewSecretClient(test.input.secrets, test.input.secretErr),
				settingClient: stub.NewSettingClient(test.input.settings, test.input.settingErr),
			}

			gotErr := p.Parse(&test.input.s, test.input.options...)

			if diff := cmp.Diff(test.want, test.input.s, cmp.AllowUnexported(Struct{})); diff != "" {
				t.Errorf("Parse() = unexpected result (-want +got)\n%s\n", diff)
			}

			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Unexpected result, should return error\n")
			}
		})
	}
}

func TestSetupCredential(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			cloud   cloud.Cloud
			options Entra
		}
		want    auth.Credential
		wantErr error
	}{
		{
			name: "credential settings from environment (managed identity)",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{},
			want: &identity.ManagedIdentityCredential{},
		},
		{
			name: "credential settings from options (client secret credential)",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{
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
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{
					TenantID:     "1111",
					ClientID:     "2222",
					Certificates: []*x509.Certificate{{}},
					PrivateKey:   &rsa.PrivateKey{},
				},
			},
			want: &identity.ClientCredential{},
		},
		{
			name: "credential settings from options (client assertion credential)",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{
					TenantID: "1111",
					ClientID: "2222",
					Assertion: func() (string, error) {
						return "assertion", nil
					},
				},
			},
			want: &identity.ClientCredential{},
		},
		{
			name: "credential settings from options (azure cli)",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{AzureCLICredential: true},
			},
			want: &identity.AzureCLICredential{},
		},
		{
			name: "credential settings from options (managed identity)",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{ManagedIdentity: true},
			},
			want: &identity.ManagedIdentityCredential{},
		},
		{
			name: "error setting up client certificate credential",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{
					TenantID:        "1111",
					ClientID:        "2222",
					certificatePath: "certificate",
				},
			},
			wantErr: errors.New("invalid path"),
		},
		{
			name: "error setting up managed identity credential",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{
					ManagedIdentity: true,
				},
			},
			wantErr: errTestManagedIdentity,
		},
		{
			name: "error - cannot determine credential",
			input: struct {
				cloud   cloud.Cloud
				options Entra
			}{
				options: Entra{
					TenantID: "1111",
				},
			},
			wantErr: ErrInvalidCredential,
		},
	}

	var oldCertificateAndKey = certificateAndKey

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(func() {
				certificateAndKey = oldCertificateAndKey
			})

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
			newClientAssertionCredential = func(_, _ string, _ func() (string, error), _ ...identity.CredentialOption) (*identity.ClientCredential, error) {
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
			newAzureCLICredential = func(_ ...identity.CredentialOption) (*identity.AzureCLICredential, error) {
				if test.wantErr != nil {
					return nil, test.wantErr
				}
				return &identity.AzureCLICredential{}, nil
			}
			certificateAndKey = func(_, _ string) ([]*x509.Certificate, *rsa.PrivateKey, error) {
				if test.wantErr != nil {
					return nil, nil, test.wantErr
				}
				return []*x509.Certificate{{}}, &rsa.PrivateKey{}, nil
			}

			got, gotErr := setupCredential(test.input.cloud, test.input.options)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(mockCredential{}), cmpopts.IgnoreUnexported(identity.ClientCredential{}, identity.ManagedIdentityCredential{}, identity.AzureCLICredential{})); diff != "" {
				t.Errorf("setupCredential() = unexpected (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("setupCredential() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestCertificateAndKey(t *testing.T) {
	cert, err := testutils.CreateCertificate()
	if err != nil {
		t.Fatalf("Unexpected error creating certificate: %v\n", err)
	}

	var tests = []struct {
		name  string
		input struct {
			certificate, certificatePath string
		}
		want struct {
			certificate []*x509.Certificate
			key         *rsa.PrivateKey
		}
		wantErr error
	}{
		{
			name: "certificate provided",
			input: struct {
				certificate, certificatePath string
			}{
				certificate: base64.StdEncoding.EncodeToString(joinBytes(cert.RawRSAKey, cert.RawCert)),
			},
			want: struct {
				certificate []*x509.Certificate
				key         *rsa.PrivateKey
			}{
				certificate: []*x509.Certificate{cert.Cert},
				key:         cert.RSAKey,
			},
		},
		{
			name: "certificate path provided",
			input: struct {
				certificate, certificatePath string
			}{
				certificatePath: "test-cert.pem",
			},
			want: struct {
				certificate []*x509.Certificate
				key         *rsa.PrivateKey
			}{
				certificate: []*x509.Certificate{cert.Cert},
				key:         cert.RSAKey,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if len(test.input.certificatePath) > 0 {
				certFile, err := testutils.WriteCertificateFile(filepath.Join(os.TempDir(), test.input.certificatePath), cert.RawRSAKey, cert.RawCert)
				if err != nil {
					t.Fatalf("Unexpected error writing certificate file: %v\n", err)
				}
				defer os.Remove(certFile.Name())
			}

			gotCerts, gotKey, gotErr := certificateAndKey(test.input.certificate, filepath.Join(os.TempDir(), test.input.certificatePath))

			if diff := cmp.Diff(test.want.certificate, gotCerts); diff != "" {
				t.Errorf("certificateAndKey() = unexpected certificate (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.want.key, gotKey); diff != "" {
				t.Errorf("certificateAndKey() = unexpected key (-want +got)\n%s\n", diff)
			}

			if test.wantErr == nil && gotErr != nil {
				t.Errorf("Unexpected error: %v\n", gotErr)
			}
		})
	}
}

type mockCredential struct{}

func (c mockCredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	return auth.Token{}, nil
}

var (
	errTestManagedIdentity = errors.New("managed identity error")
)

func joinBytes(b ...[]byte) []byte {
	var buf bytes.Buffer
	for _, v := range b {
		buf.Write(v)
	}
	return buf.Bytes()
}

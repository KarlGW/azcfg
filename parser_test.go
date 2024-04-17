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
	"github.com/KarlGW/azcfg/azure/cloud"
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
				timeout:       time.Second * 10,
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
				timeout:      time.Second * 10,
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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

			got, gotErr := setupCredential(test.input.cloud, test.input.options)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(mockCredential{}), cmpopts.IgnoreUnexported(identity.ClientCredential{}, identity.ManagedIdentityCredential{})); diff != "" {
				t.Errorf("setupCredential() = unexpected (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("setupCredential() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

type mockCredential struct{}

func (c mockCredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	return auth.Token{}, nil
}

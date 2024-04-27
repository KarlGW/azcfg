package azcfg

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/KarlGW/azcfg/stub"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestOptions(t *testing.T) {
	var tests = []struct {
		name  string
		input Option
		want  Options
	}{
		{
			name:  "WithCredential",
			input: WithCredential(mockCredential{}),
			want: Options{
				Credential: mockCredential{},
			},
		},
		{
			name:  "WithKeyVault",
			input: WithKeyVault("vault"),
			want: Options{
				KeyVault: "vault",
			},
		},
		{
			name:  "WithAppConfiguration",
			input: WithAppConfiguration("appconfig"),
			want: Options{
				AppConfiguration: "appconfig",
			},
		},
		{
			name:  "WithConcurrency",
			input: WithConcurrency(5),
			want: Options{
				Concurrency: 5,
			},
		},
		{
			name:  "WithTimeout",
			input: WithTimeout(time.Second * 5),
			want: Options{
				Timeout: time.Second * 5,
			},
		},
		{
			name:  "WithClientSecretCredential",
			input: WithClientSecretCredential("1111", "2222", "3333"),
			want: Options{
				Authentication: Authentication{
					Entra: Entra{
						TenantID:     "1111",
						ClientID:     "2222",
						ClientSecret: "3333",
					},
				},
			},
		},
		{
			name:  "WithClientCertificateCredential",
			input: WithClientCertificateCredential("1111", "2222", []*x509.Certificate{}, &rsa.PrivateKey{}),
			want: Options{
				Authentication: Authentication{
					Entra: Entra{
						TenantID:     "1111",
						ClientID:     "2222",
						Certificates: []*x509.Certificate{},
						PrivateKey:   &rsa.PrivateKey{},
					},
				},
			},
		},
		{
			name: "WithClientAssertionCredential",
			input: WithClientAssertionCredential("1111", "2222", func() (string, error) {
				return "assertion", nil
			}),
			want: Options{
				Authentication: Authentication{
					Entra: Entra{
						TenantID: "1111",
						ClientID: "2222",
						Assertion: func() (string, error) {
							return "assertion", nil
						},
					},
				},
			},
		},
		{
			name:  "WithManagedIdentity",
			input: WithManagedIdentity("2222"),
			want: Options{
				Authentication: Authentication{
					Entra: Entra{
						ClientID:        "2222",
						ManagedIdentity: true,
					},
				},
			},
		},
		{
			name:  "WithManagedIdentityIMDSDialTimeout",
			input: WithManagedIdentityIMDSDialTimeout(time.Second * 10),
			want: Options{
				Authentication: Authentication{
					Entra: Entra{
						ManagedIdentityIMDSDialTimeout: time.Second * 10,
					},
				},
			},
		},
		{
			name:  "WithAzureCLICredential",
			input: WithAzureCLICredential(),
			want: Options{
				Authentication: Authentication{
					Entra: Entra{
						AzureCLICredential: true,
					},
				},
			},
		},
		{
			name:  "WithAppConfigurationAccessKey",
			input: WithAppConfigurationAccessKey("1111", "2222"),
			want: Options{
				Authentication: Authentication{
					AppConfigurationAccessKey: AppConfigurationAccessKey{
						ID:     "1111",
						Secret: "2222",
					},
				},
			},
		},
		{
			name:  "WithAppConfigurationConnectionString",
			input: WithAppConfigurationConnectionString("Endpoint=https://config.azconfig.io;Id=1111;Secret=2222"),
			want: Options{
				Authentication: Authentication{
					AppConfigurationConnectionString: "Endpoint=https://config.azconfig.io;Id=1111;Secret=2222",
				},
			},
		},
		{
			name:  "WithSecretClient",
			input: WithSecretClient(stub.NewSecretClient(nil, nil)),
			want: Options{
				SecretClient: stub.SecretClient{},
			},
		},
		{
			name:  "WithSettingClient",
			input: WithSettingClient(stub.NewSettingClient(nil, nil)),
			want: Options{
				SettingClient: stub.SettingClient{},
			},
		},
		{
			name:  "WithLabel",
			input: WithLabel("label"),
			want: Options{
				Label: "label",
			},
		},
		{
			name:  "WithLabels",
			input: WithLabels(map[string]string{"setting1": "prod"}),
			want: Options{
				Labels: map[string]string{"setting1": "prod"},
			},
		},
		{
			name:  "WithCloud",
			input: WithCloud(cloud.AzurePublic),
			want: Options{
				Cloud: cloud.AzurePublic,
			},
		},
		{
			name:  "(invalid) WithCloud",
			input: WithCloud("invalid"),
			want: Options{
				Cloud: cloud.AzurePublic,
			},
		},
		{
			name: "WithRetryPolicy",
			input: WithRetryPolicy(RetryPolicy{
				MinDelay: time.Second,
				MaxDelay: time.Second * 5,
			}),
			want: Options{
				RetryPolicy: RetryPolicy{
					MinDelay: time.Second,
					MaxDelay: time.Second * 5,
				},
			},
		},
	}

	for _, test := range tests {
		got := Options{}
		test.input(&got)

		if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Options{}, mockCredential{}, Entra{}), cmpopts.IgnoreUnexported(stub.SecretClient{}, stub.SettingClient{}), cmpopts.IgnoreFields(Entra{}, "PrivateKey"), cmp.Comparer(compareAssertionFunc)); diff != "" {
			t.Errorf("%s() = unexpected result (-want +got)\n%s\n", test.name, diff)
		}
	}
}

func compareAssertionFunc(x, y func() (string, error)) bool {
	if x == nil || y == nil {
		return true
	}
	xResult, xErr := x()
	yResult, yErr := y()
	return xResult == yResult && xErr == yErr
}

package azcfg

import (
	"testing"
	"time"

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
				TenantID:     "1111",
				ClientID:     "2222",
				ClientSecret: "3333",
			},
		},
		{
			name:  "WithManagedIdentity",
			input: WithManagedIdentity("2222"),
			want: Options{
				ClientID:           "2222",
				UseManagedIdentity: true,
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
	}

	for _, test := range tests {
		got := Options{}
		test.input(&got)

		if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(mockCredential{}), cmpopts.IgnoreUnexported(stub.SecretClient{}, stub.SettingClient{}), cmpopts.IgnoreFields(Options{}, "PrivateKey")); diff != "" {
			t.Errorf("%s = unexpected result (-want +got)\n%s\n", test.name, diff)
		}
	}
}

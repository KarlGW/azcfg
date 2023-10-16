package stub

import (
	"errors"
	"testing"

	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewSecretClient(t *testing.T) {
	t.Run("NewSecretClient", func(t *testing.T) {
		want := SecretClient{
			secrets: map[string]secret.Secret{},
			err:     errors.New("test"),
		}

		got := NewSecretClient(map[string]string{
			"secret": "value",
		}, errors.New("test"))

		if diff := cmp.Diff(want, got, cmp.AllowUnexported(SecretClient{}), cmpopts.IgnoreUnexported(SecretClient{})); diff != "" {
			t.Errorf("NewSecretClient() = unexpected result (-want +got)\n%s\n", diff)
		}
	})
}

func TestSecretClient_Get(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			names   []string
			secrets map[string]string
			err     error
		}
		want    map[string]secret.Secret
		wantErr error
	}{
		{
			name: "Get secrets",
			input: struct {
				names   []string
				secrets map[string]string
				err     error
			}{
				names: []string{"secret"},
				secrets: map[string]string{
					"secret": "value",
				},
				err: nil,
			},
			want: map[string]secret.Secret{
				"secret": {
					Value: "value",
				},
			},
			wantErr: nil,
		},
		{
			name: "Get error",
			input: struct {
				names   []string
				secrets map[string]string
				err     error
			}{
				names: []string{"secret"},
				secrets: map[string]string{
					"secret": "value",
				},
				err: errGetSecrets,
			},
			want:    nil,
			wantErr: errGetSecrets,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cl := NewSecretClient(test.input.secrets, test.input.err)
			got, gotErr := cl.Get(test.input.names...)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Get() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Get() = unexpected error (-want +got)\n%s\b", diff)
			}
		})
	}
}

var errGetSecrets = errors.New("err")

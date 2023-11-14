package stub

import (
	"errors"
	"testing"

	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
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

func TestSecretClient_GetSecrets(t *testing.T) {
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
			got, gotErr := cl.GetSecrets(test.input.names)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("GetSecrets() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("GetSecrets() = unexpected error (-want +got)\n%s\b", diff)
			}
		})
	}
}

func TestNewSettingClient(t *testing.T) {
	t.Run("NewSettingClient", func(t *testing.T) {
		want := SettingClient{
			settings: map[string]setting.Setting{},
			err:      errors.New("test"),
		}

		got := NewSettingClient(map[string]string{
			"setting": "value",
		}, errors.New("test"))

		if diff := cmp.Diff(want, got, cmp.AllowUnexported(SettingClient{}), cmpopts.IgnoreUnexported(SettingClient{})); diff != "" {
			t.Errorf("NewSettingCLient() = unexpected result (-want +got)\n%s\n", diff)
		}
	})
}

func TestSettingClient_GetSettings(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			keys     []string
			settings map[string]string
			err      error
		}
		want    map[string]setting.Setting
		wantErr error
	}{
		{
			name: "Get settings",
			input: struct {
				keys     []string
				settings map[string]string
				err      error
			}{
				keys: []string{"setting"},
				settings: map[string]string{
					"setting": "value",
				},
				err: nil,
			},
			want: map[string]setting.Setting{
				"setting": {
					Value: "value",
				},
			},
			wantErr: nil,
		},
		{
			name: "Get error",
			input: struct {
				keys     []string
				settings map[string]string
				err      error
			}{
				keys: []string{"setting"},
				settings: map[string]string{
					"setting": "value",
				},
				err: errGetSettings,
			},
			want:    nil,
			wantErr: errGetSettings,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cl := NewSettingClient(test.input.settings, test.input.err)
			got, gotErr := cl.GetSettings(test.input.keys)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("GetSettings() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("GetSettings() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

var (
	errGetSecrets  = errors.New("err")
	errGetSettings = errors.New("err")
)

package azcfg

import (
	"testing"

	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
	"github.com/google/go-cmp/cmp"
)

func TestRequiredErrorMessage_Secret(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			secrets  map[string]secret.Secret
			required []string
		}
		want string
	}{
		{
			name: "no required",
			input: struct {
				secrets  map[string]secret.Secret
				required []string
			}{
				secrets:  map[string]secret.Secret{},
				required: []string{},
			},
			want: "",
		},
		{
			name: "1 required",
			input: struct {
				secrets  map[string]secret.Secret
				required []string
			}{
				secrets: map[string]secret.Secret{
					"secret1": {Value: ""},
				},
				required: []string{
					"secret1",
				},
			},
			want: "secret: secret1 is required",
		},
		{
			name: "2 required",
			input: struct {
				secrets  map[string]secret.Secret
				required []string
			}{
				secrets: map[string]secret.Secret{
					"secret1": {Value: ""},
					"secret2": {Value: ""},
				},
				required: []string{
					"secret1",
					"secret2",
				},
			},
			want: "secrets: secret1 and secret2 are required",
		},
		{
			name: "3 required",
			input: struct {
				secrets  map[string]secret.Secret
				required []string
			}{
				secrets: map[string]secret.Secret{
					"secret1": {Value: ""},
					"secret2": {Value: ""},
					"secret3": {Value: ""},
				},
				required: []string{
					"secret1",
					"secret2",
					"secret3",
				},
			},
			want: "secrets: secret1, secret2 and secret3 are required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := requiredErrorMessage(test.input.secrets, test.input.required, "secret")

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("requiredErrorMessage() = unexpected result, (-want, +got)\n%s\n", diff)
			}
		})
	}
}

func TestRequiredErrorMessage_Setting(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			settings map[string]setting.Setting
			required []string
		}
		want string
	}{
		{
			name: "no required",
			input: struct {
				settings map[string]setting.Setting
				required []string
			}{
				settings: map[string]setting.Setting{},
				required: []string{},
			},
			want: "",
		},
		{
			name: "1 required",
			input: struct {
				settings map[string]setting.Setting
				required []string
			}{
				settings: map[string]setting.Setting{
					"setting1": {Value: ""},
				},
				required: []string{
					"setting1",
				},
			},
			want: "setting: setting1 is required",
		},
		{
			name: "2 required",
			input: struct {
				settings map[string]setting.Setting
				required []string
			}{
				settings: map[string]setting.Setting{
					"setting1": {Value: ""},
					"setting2": {Value: ""},
				},
				required: []string{
					"setting1",
					"setting2",
				},
			},
			want: "settings: setting1 and setting2 are required",
		},
		{
			name: "3 required",
			input: struct {
				settings map[string]setting.Setting
				required []string
			}{
				settings: map[string]setting.Setting{
					"setting1": {Value: ""},
					"setting2": {Value: ""},
					"setting3": {Value: ""},
				},
				required: []string{
					"setting1",
					"setting2",
					"setting3",
				},
			},
			want: "settings: setting1, setting2 and setting3 are required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := requiredErrorMessage(test.input.settings, test.input.required, "setting")

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("requiredErrorMessage() = unexpected result, (-want, +got)\n%s\n", diff)
			}
		})
	}
}

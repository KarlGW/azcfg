package azcfg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRequiredErrorMessage(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			secrets  map[string]string
			required []string
		}
		want string
	}{
		{
			name: "no required",
			input: struct {
				secrets  map[string]string
				required []string
			}{
				secrets:  map[string]string{},
				required: []string{},
			},
			want: "",
		},
		{
			name: "1 required",
			input: struct {
				secrets  map[string]string
				required []string
			}{
				secrets: map[string]string{
					"secret1": "",
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
				secrets  map[string]string
				required []string
			}{
				secrets: map[string]string{
					"secret1": "",
					"secret2": "",
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
				secrets  map[string]string
				required []string
			}{
				secrets: map[string]string{
					"secret1": "",
					"secret2": "",
					"secret3": "",
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
			got := requiredErrorMessage(test.input.secrets, test.input.required)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("requiredErrorMessage(%+v, %+v) = unexpected result, (-want, +got)\n%s\n", test.input.secrets, test.input.secrets, diff)
			}
		})
	}
}

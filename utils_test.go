package azcfg

import (
	"testing"

	"github.com/KarlGW/azcfg/azure/cloud"
	"github.com/google/go-cmp/cmp"
)

func TestSplitTrim(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		sep   string
		want  []string
	}{
		{
			name:  "nosep",
			input: "aaaa,bbbb, cccc,     dddd",
			want:  []string{"aaaa", "bbbb", "cccc", "dddd"},
		},
		{
			name:  "comma",
			input: "aaaa,bbbb, cccc,     dddd",
			sep:   ",",
			want:  []string{"aaaa", "bbbb", "cccc", "dddd"},
		},
		{
			name:  "colon",
			input: "aaaa:bbbb: cccc:     dddd",
			sep:   ":",
			want:  []string{"aaaa", "bbbb", "cccc", "dddd"},
		},
		{
			name: "no value",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := splitTrim(test.input, test.sep)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("splitTrim(%q, %q) = unexpected result, (-want, +got)\n%s\n", test.input, test.sep, diff)
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
			input: "setting1=prod,setting2",
			want: map[string]string{
				"setting1": "prod",
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

func TestParseCloud(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  cloud.Cloud
	}{
		{
			name: "empty string",
			want: cloud.AzurePublic,
		},
		{
			name:  "Azure",
			input: "Azure",
			want:  cloud.AzurePublic,
		},
		{
			name:  "AzurePublic",
			input: "AzurePublic",
			want:  cloud.AzurePublic,
		},
		{
			name:  "Public",
			input: "Public",
			want:  cloud.AzurePublic,
		},
		{
			name:  "AzureGovernment",
			input: "AzureGovernment",
			want:  cloud.AzureGovernment,
		},
		{
			name:  "Government",
			input: "Government",
			want:  cloud.AzureGovernment,
		},
		{
			name:  "AzureChina",
			input: "AzureChina",
			want:  cloud.AzureChina,
		},
		{
			name:  "China",
			input: "China",
			want:  cloud.AzureChina,
		},
		{
			name:  "non-existent cloud",
			input: "NonExistent",
			want:  cloud.AzurePublic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseCloud(test.input)

			if test.want != got {
				t.Errorf("parseCloud() = unexpected result, want: %s, got: %s\n", test.want, got)
			}
		})
	}
}

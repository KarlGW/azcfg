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

func TestParseBool(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  bool
	}{
		{
			name: "empty string",
			want: false,
		},
		{
			name:  "true",
			input: "true",
			want:  true,
		},
		{
			name:  "false",
			input: "false",
			want:  false,
		},
		{
			name:  "invalid",
			input: "invalid",
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseBool(test.input)

			if test.want != got {
				t.Errorf("parseBool() = unexpected result, want: %t, got: %t\n", test.want, got)
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
			name:  "with comma-separated key-value pairs",
			input: "setting1=prod,setting2=test",
			want: map[string]string{
				"setting1": "prod",
				"setting2": "test",
			},
		},
		{
			name:  "with comma-separated key-value pairs (spaces in string)",
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
			name:  "with malformed second key-value pair",
			input: "setting1=prod,setting2",
			want: map[string]string{
				"setting1": "prod",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseCSVKVP(test.input)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("parseCSVKVP() = unexpected result (-want +got)\n%s\n", diff)
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

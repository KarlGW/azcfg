package cloud

import "testing"

func TestCloud_Valid(t *testing.T) {
	var tests = []struct {
		name  string
		input Cloud
		want  bool
	}{
		{
			name:  "AzurePublic",
			input: AzurePublic,
			want:  true,
		},
		{
			name:  "AzureGovernment",
			input: AzureGovernment,
			want:  true,
		},
		{
			name:  "AzureChina",
			input: AzureChina,
			want:  true,
		},
		{
			name:  "Invalid",
			input: "Invalid",
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.input.Valid()

			if test.want != got {
				t.Errorf("Valid() = unexpected result, want: %v, got: %v\n", test.want, got)
			}
		})
	}
}

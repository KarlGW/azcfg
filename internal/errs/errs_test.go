package errs

import (
	"errors"
	"testing"
)

func TestErrsError(t *testing.T) {
	var tests = []struct {
		name  string
		input Errors
		want  string
	}{
		{
			name:  "one error",
			input: Errors{errors.New("error1")},
			want:  "error1",
		},
		{
			name:  "multiple errors",
			input: Errors{errors.New("error1"), errors.New("error2"), errors.New("error3")},
			want:  "error1\nerror2\nerror3",
		},
	}

	for _, test := range tests {
		got := test.input.Error()

		if test.want != got {
			t.Errorf("Unexpected result, want: %s, got: %s", test.want, got)
		}
	}
}

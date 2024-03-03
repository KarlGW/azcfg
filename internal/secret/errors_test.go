package secret

import (
	"errors"
	"testing"
)

func TestIsSecretNotFound(t *testing.T) {
	var tests = []struct {
		name  string
		input error
		want  bool
	}{
		{
			name:  "is a secretErr with error code SecretNotFound",
			input: testNewSecretError(SecretNotFound),
			want:  true,
		},
		{
			name:  "is a secretErr with error code Unauthorized",
			input: testNewSecretError("Unauthorized"),
			want:  false,
		},
		{
			name:  "is not a secretErr",
			input: errors.New("error"),
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isSecretNotFound(test.input)

			if test.want != got {
				t.Errorf("isSecretNotFound() = unexpected result, want: %v, got: %v\n", test.want, got)
			}
		})
	}
}

func testNewSecretError(code string) secretError {
	s := secretError{}
	s.Err.Code = code
	return s
}

package setting

import (
	"errors"
	"testing"
)

func TestIsSettingNotFound(t *testing.T) {
	var tests = []struct {
		name  string
		input error
		want  bool
	}{
		{
			name:  "is a settingErr with status code 404",
			input: testNewSettingError(SettingNotFound),
			want:  true,
		},
		{
			name:  "is a settingErr with status code 400",
			input: testNewSettingError(400),
			want:  false,
		},
		{
			name:  "is not a settingErr",
			input: errors.New("error"),
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isSettingNotFound(test.input)

			if test.want != got {
				t.Errorf("isSettingNotFound() = unexpected result, want: %v, got: %v\n", test.want, got)
			}
		})
	}
}

func testNewSettingError(statusCode int) settingError {
	s := settingError{}
	s.StatusCode = statusCode
	return s
}

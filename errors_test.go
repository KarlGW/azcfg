package azcfg

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewError(t *testing.T) {
	var tests = []struct {
		name  string
		input []error
		want  *Error
	}{
		{
			name:  "no errors",
			input: []error{},
			want:  nil,
		},
		{
			name: "1 error",
			input: []error{
				ErrCredential,
			},
			want: &Error{
				errors: []error{
					ErrCredential,
				},
			},
		},
		{
			name: "2 errors",
			input: []error{
				ErrCredential,
				ErrSetValue,
			},
			want: &Error{
				errors: []error{
					ErrCredential,
					ErrSetValue,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := newError(test.input...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Error{}), ErrorTypeMatcher(test.want, got)); diff != "" {
				t.Errorf("newError() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestError_Error(t *testing.T) {
	t.Run("Error()", func(t *testing.T) {
		want := "set value error\ncredential error"
		got := newError(ErrSetValue, ErrCredential).Error()

		if want != got {
			t.Errorf("Error() = unexpected result, want: %s, got: %s\n", want, got)
		}
	})

}

func TestError_Errors(t *testing.T) {
	t.Run("Errors()", func(t *testing.T) {
		want := []error{ErrCredential, ErrSetValue}
		errs := newError(ErrCredential, ErrSetValue).Errors()

		for i, got := range errs {
			if diff := cmp.Diff(want[i], got, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Errors() = unexpected result (-want +got)\n%s\n", diff)
			}
		}
	})

}

func TestNewRequiredFieldsError(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			values         map[string]string
			requiredFields []requiredFields
		}
		want *RequiredFieldsError
	}{
		{
			name: "no required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values:         map[string]string{},
				requiredFields: []requiredFields{},
			},
			want: nil,
		},
		{
			name: "1 secret is required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"secret1": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"secret1"},
						t: "secret",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "secret: secret1 is required",
				required: []string{"secret1"},
				missing:  []string{"secret1"},
			},
		},
		{
			name: "2 secrets are required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"secret1": "",
					"secret2": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"secret1", "secret2"},
						t: "secret",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "secrets: secret1 and secret2 are required",
				required: []string{"secret1", "secret2"},
				missing:  []string{"secret1", "secret2"},
			},
		},
		{
			name: "4 secrets are required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"secret1": "",
					"secret2": "",
					"secret3": "",
					"secret4": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"secret1", "secret2", "secret3", "secret4"},
						t: "secret",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "secrets: secret1, secret2, secret3 and secret4 are required",
				required: []string{"secret1", "secret2", "secret3", "secret4"},
				missing:  []string{"secret1", "secret2", "secret3", "secret4"},
			},
		},
		{
			name: "4 secrets are required, 2 missing",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"secret1": "",
					"secret2": "value2",
					"secret3": "value3",
					"secret4": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"secret1", "secret2", "secret3", "secret4"},
						t: "secret",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "secrets: secret1 and secret4 are required",
				required: []string{"secret1", "secret2", "secret3", "secret4"},
				missing:  []string{"secret1", "secret4"},
			},
		},
		{
			name: "1 setting is required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"secret1": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"setting1"},
						t: "setting",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "setting: setting1 is required",
				required: []string{"setting1"},
				missing:  []string{"setting1"},
			},
		},
		{
			name: "2 settings are required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"setting1": "",
					"setting2": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"setting1", "setting2"},
						t: "setting",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "settings: setting1 and setting2 are required",
				required: []string{"setting1", "setting2"},
				missing:  []string{"setting1", "setting2"},
			},
		},
		{
			name: "4 settings are required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"setting1": "",
					"setting2": "",
					"setting3": "",
					"setting4": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"setting1", "setting2", "setting3", "setting4"},
						t: "setting",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "settings: setting1, setting2, setting3 and setting4 are required",
				required: []string{"setting1", "setting2", "setting3", "setting4"},
				missing:  []string{"setting1", "setting2", "setting3", "setting4"},
			},
		},
		{
			name: "4 settings are required, 2 missing",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"setting1": "",
					"setting2": "value2",
					"setting3": "value3",
					"setting4": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"setting1", "setting2", "setting3", "setting4"},
						t: "setting",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "settings: setting1 and setting4 are required",
				required: []string{"setting1", "setting2", "setting3", "setting4"},
				missing:  []string{"setting1", "setting4"},
			},
		},
		{
			name: "settings and settings are required",
			input: struct {
				values         map[string]string
				requiredFields []requiredFields
			}{
				values: map[string]string{
					"secret1":  "",
					"secret2":  "",
					"secret3":  "",
					"secret4":  "",
					"setting1": "",
					"setting2": "",
					"setting3": "",
					"setting4": "",
				},
				requiredFields: []requiredFields{
					{
						f: []string{"secret1", "secret2", "secret3", "secret4"},
						t: "secret",
					},
					{
						f: []string{"setting1", "setting2", "setting3", "setting4"},
						t: "setting",
					},
				},
			},
			want: &RequiredFieldsError{
				message:  "secrets: secret1, secret2, secret3 and secret4 are required\nsettings: setting1, setting2, setting3 and setting4 are required",
				required: []string{"secret1", "secret2", "secret3", "secret4", "setting1", "setting2", "setting3", "setting4"},
				missing:  []string{"secret1", "secret2", "secret3", "secret4", "setting1", "setting2", "setting3", "setting4"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := newRequiredFieldsError(test.input.values, test.input.requiredFields...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(RequiredFieldsError{})); diff != "" {
				t.Errorf("newRequiredFieldsError() = unexpected result (-want +got)\n%s\n", diff)
			}

			if test.want != nil {
				if diff := cmp.Diff(test.want.Required(), got.Required()); diff != "" {
					t.Errorf("Required() = unexpected result (-want +got)\n%s\n", diff)
				}

				if diff := cmp.Diff(test.want.Missing(), got.Missing()); diff != "" {
					t.Errorf("Missing() = unexpected result (-want +got)\n%s\n", diff)
				}
			}
		})
	}
}

// ErrorTypeMatcher is a custom matcher for comparing two errors.
// It handles sentinel errors and custom error types.
func ErrorTypeMatcher(x, y error) cmp.Option {
	return cmp.Comparer(func(x, y error) bool {
		if x == nil || y == nil {
			return x == y
		}

		xType := reflect.TypeOf(x)
		yType := reflect.TypeOf(y)

		if xType != yType {
			return false
		}

		if xType.Kind() == reflect.Struct && yType.Kind() == reflect.Struct {
			return errors.Is(x, y)
		}

		xValue := reflect.ValueOf(x)
		yValue := reflect.ValueOf(y)

		if xValue.IsZero() && yValue.IsZero() {
			return true
		}

		xValue = xValue.Elem()
		yValue = yValue.Elem()

		for i := 0; i < xValue.NumField(); i++ {
			if xValue.Type().Field(i).PkgPath != "" {
				continue
			}
			if !cmp.Equal(xValue.Field(i).Interface(), yValue.Field(i).Interface()) {
				return false
			}
		}
		return true
	})
}

package azcfg

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/KarlGW/azcfg/internal/secret"
	"github.com/KarlGW/azcfg/internal/setting"
	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	var tests = []struct {
		name    string
		input   Struct
		want    Struct
		wantErr error
	}{
		{
			name: "parse",
			input: Struct{
				String:           "initial string",
				StringPtr:        toPtr("initial string ptr"),
				StringSetting:    "initial string setting",
				StringSettingPtr: toPtr("initial string setting ptr"),
				Bool:             false,
				BoolPtr:          toPtr(false),
				BoolSetting:      false,
				BoolSettingPtr:   toPtr(false),
				Duration:         time.Second * 3,
				DurationPtr:      toPtr(time.Second * 3),
				Empty:            "",
				EmptySetting:     "",
				NestedStructA: NestedStructA{
					Int:           1,
					Int64:         1,
					IntSetting:    1,
					Int64Setting:  1,
					Uint:          1,
					Uint64:        1,
					UintSetting:   1,
					Uint64Setting: 1,
					IntNotParse:   1,
					NestedNestedStruct: NestedNestedStruct{
						NestedString: "initial nested string",
					},
				},
				NestedStructB: &NestedStructB{
					Float64:    1,
					Float64Ptr: toPtr[float64](1),
				},
				unexportedNestedStructA: NestedStructA{
					Int:         2,
					IntNotParse: 2,
				},
				unexportedField:        "initial string",
				unexportedSettingField: "initial string",
			},
			want: Struct{
				String:           "new string",
				StringPtr:        toPtr("new string ptr"),
				Bool:             true,
				BoolPtr:          toPtr(true),
				BoolSetting:      true,
				BoolSettingPtr:   toPtr(true),
				StringSetting:    "new string setting",
				StringSettingPtr: toPtr("new string setting ptr"),
				Duration:         time.Second * 1,
				DurationPtr:      toPtr(time.Second * 2),
				Complex64:        5 + 12i,
				Complex64Ptr:     toPtr[complex64](5 + 12i),
				Complex128:       5 + 12i,
				Complex128Ptr:    toPtr[complex128](5 + 12i),
				NestedStructA: NestedStructA{
					Int:                   100,
					Int64:                 100,
					IntSetting:            100,
					Int64Setting:          100,
					IntNotParse:           1,
					Uint:                  100,
					Uint64:                100,
					UintSetting:           100,
					Uint64Setting:         100,
					StringSlice:           []string{"a", "b", "c"},
					StringSlicePtr:        []*string{toPtr("a"), toPtr("b"), toPtr("c")},
					StringSliceSetting:    []string{"a", "b", "c"},
					StringSliceSettingPtr: []*string{toPtr("a"), toPtr("b"), toPtr("c")},
					IntSlice:              []int{1, 2, 3},
					IntSlicePtr:           []*int{toPtr(1), toPtr(2), toPtr(3)},
					IntSliceSetting:       []int{1, 2, 3},
					IntSliceSettingPtr:    []*int{toPtr(1), toPtr(2), toPtr(3)},
					NestedNestedStruct: NestedNestedStruct{
						NestedString: "new nested string",
					},
				},
				NestedStructB: &NestedStructB{
					Float64:           100,
					Float64Ptr:        toPtr[float64](100),
					Float64Setting:    100,
					Float64SettingPtr: toPtr[float64](100),
				},
				unexportedNestedStructA: NestedStructA{
					Int:         2,
					IntNotParse: 2,
				},
				unexportedField:        "initial string",
				unexportedSettingField: "initial string",
			},
		},
		{
			name: "parse - error getting secrets and settings",
			input: Struct{
				String:           "initial string",
				StringPtr:        toPtr("initial string ptr"),
				StringSetting:    "initial string setting",
				StringSettingPtr: toPtr("initial string setting ptr"),
				Bool:             false,
				BoolPtr:          toPtr(false),
				BoolSetting:      false,
				BoolSettingPtr:   toPtr(false),
				Empty:            "",
				EmptySetting:     "",
				NestedStructA: NestedStructA{
					Int:           1,
					Int64:         1,
					IntSetting:    1,
					Int64Setting:  1,
					Uint:          1,
					Uint64:        1,
					UintSetting:   1,
					Uint64Setting: 1,
					IntNotParse:   1,
					NestedNestedStruct: NestedNestedStruct{
						NestedString: "initial nested string",
					},
				},
				NestedStructB: &NestedStructB{
					Float64:    1,
					Float64Ptr: toPtr[float64](1),
				},
				unexportedNestedStructA: NestedStructA{
					Int:         2,
					IntNotParse: 2,
				},
				unexportedField:        "initial string",
				unexportedSettingField: "initial string",
			},
			want: Struct{
				String:           "initial string",
				StringPtr:        toPtr("initial string ptr"),
				StringSetting:    "initial string setting",
				StringSettingPtr: toPtr("initial string setting ptr"),
				Bool:             false,
				BoolPtr:          toPtr(false),
				BoolSetting:      false,
				BoolSettingPtr:   toPtr(false),
				Empty:            "",
				EmptySetting:     "",
				NestedStructA: NestedStructA{
					Int:           1,
					Int64:         1,
					IntSetting:    1,
					Int64Setting:  1,
					Uint:          1,
					Uint64:        1,
					UintSetting:   1,
					Uint64Setting: 1,
					IntNotParse:   1,
					NestedNestedStruct: NestedNestedStruct{
						NestedString: "initial nested string",
					},
				},
				NestedStructB: &NestedStructB{
					Float64:    1,
					Float64Ptr: toPtr[float64](1),
				},
				unexportedNestedStructA: NestedStructA{
					Int:         2,
					IntNotParse: 2,
				},
				unexportedField:        "initial string",
				unexportedSettingField: "initial string",
			},
			wantErr: errors.New("error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secretClient := mockSecretClient{err: test.wantErr}
			settingClient := mockSettingClient{err: test.wantErr}

			gotErr := parse(context.Background(), &test.input, parseOptions{secretClient: secretClient, settingClient: settingClient})
			if diff := cmp.Diff(test.want, test.input, cmp.AllowUnexported(Struct{})); diff != "" {
				t.Errorf("parse() = unexpected result, (-want, +got)\n%s\n", diff)
			}

			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Unexpected result, should return error\n")
			}
		})
	}
}

func TestParseRequired(t *testing.T) {
	var tests = []struct {
		name    string
		input   StructWithRequired
		wantErr error
	}{
		{
			name:  "required",
			input: StructWithRequired{},
			wantErr: &RequiredFieldsError{
				errors: []error{
					requiredSecretsError{message: requiredErrorMessage(map[string]secret.Secret{"empty": {}, "empty-float64": {}}, []string{"empty", "empty-float64"}, "secret")},
					requiredSettingsError{message: requiredErrorMessage(map[string]setting.Setting{"empty-setting": {}}, []string{"empty-setting"}, "setting")},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secretClient := mockSecretClient{}
			settingClient := mockSettingClient{}

			gotErr := parse(context.Background(), &test.input, parseOptions{secretClient: secretClient, settingClient: settingClient})
			if test.wantErr != nil && gotErr == nil {
				t.Errorf("Unexpected result, should return error\n")
			}

			if test.wantErr != nil && gotErr != nil {
				if diff := cmp.Diff(test.wantErr.Error(), gotErr.Error()); diff != "" {
					t.Errorf("parse(%+v, %+v) = unexpected result, (-want, +got)\n%s\n", test.wantErr.Error(), gotErr.Error(), diff)
				}
			}
		})
	}
}

func TestGetBitSize(t *testing.T) {
	var tests = []struct {
		name  string
		input any
		want  int
	}{
		{
			name: "uint", input: uint(1), want: strconv.IntSize,
		},
		{
			name: "uint8", input: uint8(1), want: 8,
		},
		{
			name: "uint16", input: uint16(1), want: 16,
		},
		{
			name: "uint32", input: uint32(1), want: 32,
		},
		{
			name: "uint64", input: uint64(1), want: 64,
		},
		{
			name: "int", input: int(1), want: strconv.IntSize,
		},
		{
			name: "int8", input: int8(1), want: 8,
		},
		{
			name: "int16", input: int16(1), want: 16,
		},
		{
			name: "int32", input: int32(1), want: 32,
		},
		{
			name: "int64", input: int64(1), want: 64,
		},
		{
			name: "float32", input: float32(1), want: 32,
		},
		{
			name: "float64", input: float64(1), want: 64,
		},
		{
			name: "complex64", input: complex64(1), want: 64,
		},
		{
			name: "complex128", input: complex128(1), want: 128,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := reflect.TypeOf(test.input)
			got := getBitSize(v.Kind())

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("getBitSize(%q) = unexpected result, (-want, +got)\n%s\n", test.input, diff)
			}
		})

	}
}

type Struct struct {
	String                  string         `secret:"string"`
	StringPtr               *string        `secret:"string-ptr"`
	StringSetting           string         `setting:"string-setting"`
	StringSettingPtr        *string        `setting:"string-setting-ptr"`
	Bool                    bool           `secret:"bool"`
	BoolPtr                 *bool          `secret:"bool-ptr"`
	BoolSetting             bool           `setting:"bool-setting"`
	BoolSettingPtr          *bool          `setting:"bool-setting-ptr"`
	Empty                   string         `secret:"empty"`
	EmptySetting            string         `setting:"empty-setting"`
	Duration                time.Duration  `secret:"duration"`
	DurationPtr             *time.Duration `secret:"duration-ptr"`
	Complex64               complex64      `secret:"complex64"`
	Complex64Ptr            *complex64     `secret:"complex64-ptr"`
	Complex128              complex128     `secret:"complex128"`
	Complex128Ptr           *complex128    `secret:"complex128-ptr"`
	NestedStructA           NestedStructA
	NestedStructB           *NestedStructB
	unexportedNestedStructA NestedStructA
	unexportedField         string `secret:"string"`
	unexportedSettingField  string `setting:"setting"`
}

type NestedStructA struct {
	Int                   int    `secret:"int"`
	IntSetting            int    `setting:"int-setting"`
	Int64                 int64  `secret:"int64"`
	Int64Setting          int64  `setting:"int64-setting"`
	Uint                  uint   `secret:"uint"`
	Uint64                uint64 `secret:"uint64"`
	UintSetting           uint   `setting:"uint-setting"`
	Uint64Setting         uint64 `setting:"uint64-setting"`
	IntNotParse           int
	StringSlice           []string  `secret:"string-slice"`
	StringSlicePtr        []*string `secret:"string-slice-ptr"`
	StringSliceSetting    []string  `setting:"string-slice-setting"`
	StringSliceSettingPtr []*string `setting:"string-slice-setting-ptr"`
	IntSlice              []int     `secret:"int-slice"`
	IntSlicePtr           []*int    `secret:"int-slice-ptr"`
	IntSliceSetting       []int     `setting:"int-slice-setting"`
	IntSliceSettingPtr    []*int    `setting:"int-slice-setting-ptr"`
	NestedNestedStruct    NestedNestedStruct
}

type NestedStructB struct {
	Float64           float64  `secret:"float64"`
	Float64Ptr        *float64 `secret:"float64-ptr"`
	Float64Setting    float64  `setting:"float64-setting"`
	Float64SettingPtr *float64 `setting:"float64-setting-ptr"`
}

type NestedNestedStruct struct {
	NestedString string `secret:"nested-string"`
}

type StructWithRequired struct {
	String                   string `secret:"string"`
	Empty                    string `secret:"empty,required"`
	EmptySetting             string `setting:"empty-setting,required"`
	NestedStructWithRequired NestedStructWithRequired
}

type NestedStructWithRequired struct {
	Int     int     `secret:"number"`
	Float64 float64 `secret:"empty-float64,required"`
}

type mockSecretClient struct {
	err error
}

func (c mockSecretClient) GetSecrets(ctx context.Context, names []string, options ...secret.Option) (map[string]secret.Secret, error) {
	if c.err != nil {
		return nil, errors.New("could not get secrets")
	}
	return responseSecrets, nil
}

var (
	responseSecrets = map[string]secret.Secret{
		"string":           {Value: "new string"},
		"string-ptr":       {Value: "new string ptr"},
		"empty":            {Value: ""},
		"int":              {Value: "100"},
		"int64":            {Value: "100"},
		"uint":             {Value: "100"},
		"uint64":           {Value: "100"},
		"float64":          {Value: "100"},
		"float64-ptr":      {Value: "100"},
		"bool":             {Value: "true"},
		"bool-ptr":         {Value: "true"},
		"nested-string":    {Value: "new nested string"},
		"string-slice":     {Value: "a,b,c"},
		"string-slice-ptr": {Value: "a,b,c"},
		"int-slice":        {Value: "1,2,3"},
		"int-slice-ptr":    {Value: "1,2,3"},
		"duration":         {Value: "1s"},
		"duration-ptr":     {Value: "2s"},
		"complex64":        {Value: "5+12i"},
		"complex64-ptr":    {Value: "5+12i"},
		"complex128":       {Value: "5+12i"},
		"complex128-ptr":   {Value: "5+12i"},
	}
)

type mockSettingClient struct {
	err error
}

func (c mockSettingClient) GetSettings(ctx context.Context, keys []string, options ...setting.Option) (map[string]setting.Setting, error) {
	time.Sleep(time.Millisecond * 10)
	if c.err != nil {
		return nil, errors.New("could not get settings")
	}
	return responseSettings, nil
}

func toPtr[V any](v V) *V {
	return &v
}

var (
	responseSettings = map[string]setting.Setting{
		"string-setting":           {Value: "new string setting"},
		"string-setting-ptr":       {Value: "new string setting ptr"},
		"bool-setting":             {Value: "true"},
		"bool-setting-ptr":         {Value: "true"},
		"empty-setting":            {Value: ""},
		"int-setting":              {Value: "100"},
		"int64-setting":            {Value: "100"},
		"uint-setting":             {Value: "100"},
		"uint64-setting":           {Value: "100"},
		"float64-setting":          {Value: "100"},
		"float64-setting-ptr":      {Value: "100"},
		"string-slice-setting":     {Value: "a,b,c"},
		"string-slice-setting-ptr": {Value: "a,b,c"},
		"int-slice-setting":        {Value: "1,2,3"},
		"int-slice-setting-ptr":    {Value: "1,2,3"},
	}
)

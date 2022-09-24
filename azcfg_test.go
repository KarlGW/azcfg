package azcfg

import (
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	secrets = map[string]string{
		"string":           "new string",
		"string-ptr":       "new string ptr",
		"int":              "100",
		"int64":            "100",
		"uint":             "100",
		"uint64":           "100",
		"float64":          "100",
		"float64-ptr":      "100",
		"bool":             "true",
		"bool-ptr":         "true",
		"nested-string":    "new nested string",
		"string-slice":     "a,b,c",
		"string-slice-ptr": "a,b,c",
		"int-slice":        "1,2,3",
		"int-slice-ptr":    "1,2,3",
	}
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
				String:    "initial string",
				Bool:      false,
				BoolPtr:   toPtr(false),
				StringPtr: toPtr("initial string ptr"),
				NestedStructA: NestedStructA{
					Int:         1,
					Int64:       1,
					Uint:        1,
					Uint64:      1,
					IntNotParse: 1,
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
				unexportedField: "initial string",
			},
			want: Struct{
				String:    "new string",
				StringPtr: toPtr("new string ptr"),
				Bool:      true,
				BoolPtr:   toPtr(true),
				NestedStructA: NestedStructA{
					Int:            100,
					Int64:          100,
					IntNotParse:    1,
					Uint:           100,
					Uint64:         100,
					StringSlice:    []string{"a", "b", "c"},
					StringSlicePtr: []*string{toPtr("a"), toPtr("b"), toPtr("c")},
					IntSlice:       []int{1, 2, 3},
					IntSlicePtr:    []*int{toPtr(1), toPtr(2), toPtr(3)},
					NestedNestedStruct: NestedNestedStruct{
						NestedString: "new nested string",
					},
				},
				NestedStructB: &NestedStructB{
					Float64:    100,
					Float64Ptr: toPtr[float64](100),
				},
				unexportedNestedStructA: NestedStructA{
					Int:         2,
					IntNotParse: 2,
				},
				unexportedField: "initial string",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := mockKeyVaultClient{}

			err := parse(&test.input, client)
			if test.wantErr == nil && err != nil {
				t.Logf("should not return error, error: %v", err)
			}

			if !cmp.Equal(test.want, test.input, cmp.AllowUnexported(Struct{})) {
				t.Log(cmp.Diff(test.want, test.input, cmp.AllowUnexported(Struct{})))
				t.Errorf("results differ")
			}

			if test.wantErr != nil && err == nil {
				t.Errorf("should return error")
			}
		})
	}
}

func TestGetFields(t *testing.T) {

}

func TestSetFields(t *testing.T) {

}

func TestSetValue(t *testing.T) {

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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := reflect.TypeOf(test.input)
			got := getBitSize(v.Kind())

			if !cmp.Equal(test.want, got) {
				t.Log(cmp.Diff(test.want, got))
				t.Errorf("results differ")
			}
		})

	}
}

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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := splitTrim(test.input, test.sep)

			if !cmp.Equal(test.want, got) {
				t.Log(cmp.Diff(test.want, got))
				t.Errorf("results differ")
			}
		})
	}
}

type Struct struct {
	String                  string  `secret:"string"`
	StringPtr               *string `secret:"string-ptr"`
	Bool                    bool    `secret:"bool"`
	BoolPtr                 *bool   `secret:"bool-ptr"`
	NestedStructA           NestedStructA
	NestedStructB           *NestedStructB
	unexportedNestedStructA NestedStructA
	unexportedField         string `secret:"string"`
}

type NestedStructA struct {
	Int                int    `secret:"int"`
	Int64              int64  `secret:"int64"`
	Uint               uint   `secret:"uint"`
	Uint64             uint64 `secret:"uint64"`
	IntNotParse        int
	StringSlice        []string  `secret:"string-slice"`
	StringSlicePtr     []*string `secret:"string-slice-ptr"`
	IntSlice           []int     `secret:"int-slice"`
	IntSlicePtr        []*int    `secret:"int-slice-ptr"`
	NestedNestedStruct NestedNestedStruct
}

type NestedStructB struct {
	Float64    float64  `secret:"float64"`
	Float64Ptr *float64 `secret:"float64-ptr"`
}

type NestedNestedStruct struct {
	NestedString string `secret:"nested-string"`
}

type mockKeyVaultClient struct {
	err bool
}

func (c mockKeyVaultClient) GetSecrets(names []string) (map[string]string, error) {
	if c.err == true {
		return nil, errors.New("could not get secret")
	}
	return secrets, nil
}

func toPtr[V any](v V) *V {
	return &v
}

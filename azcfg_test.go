package azcfg

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	initialStr             = "inital str pointer"
	newStr                 = "new string ptr"
	initialFloat64 float64 = 1
	newFloat64     float64 = 100
	initialBool            = false
	newBool                = true
	secrets                = map[string]string{
		"string":      "new string",
		"string-ptr":  "new string ptr",
		"int":         "100",
		"float64":     "100",
		"float64-ptr": "100",
		"bool":        "true",
		"bool-ptr":    "true",
	}
)

func TestParse(t *testing.T) {
	var tests = []struct {
		name    string
		input   TestStruct
		want    TestStruct
		wantErr error
	}{
		{
			name: "parse",
			input: TestStruct{
				String:    "initial string",
				Bool:      false,
				BoolPtr:   &initialBool,
				StringPtr: &initialStr,
				TestSubStructA: TestSubStructA{
					Int:         1,
					IntNotParse: 1,
				},
				TestSubStructB: &TestSubStructB{
					Float64:    1,
					Float64Ptr: &initialFloat64,
				},
			},
			want: TestStruct{
				String:    "new string",
				StringPtr: &newStr,
				Bool:      true,
				BoolPtr:   &newBool,
				TestSubStructA: TestSubStructA{
					Int:         100,
					IntNotParse: 1,
				},
				TestSubStructB: &TestSubStructB{
					Float64:    100,
					Float64Ptr: &newFloat64,
				},
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

			if !cmp.Equal(test.want, test.input) {
				t.Log(cmp.Diff(test.want, test.input))
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
			name: "int", input: int(1), want: 32,
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

type TestStruct struct {
	String         string  `secret:"string"`
	StringPtr      *string `secret:"string-ptr"`
	Bool           bool    `secret:"bool"`
	BoolPtr        *bool   `secret:"bool-ptr"`
	TestSubStructA TestSubStructA
	TestSubStructB *TestSubStructB
}

type TestSubStructA struct {
	Int         int `secret:"int"`
	IntNotParse int
}

type TestSubStructB struct {
	Float64    float64  `secret:"float64"`
	Float64Ptr *float64 `secret:"float64-ptr"`
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

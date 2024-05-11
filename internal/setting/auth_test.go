package setting

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestHMACAuthenticationHeaders(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			key     AccessKey
			method  string
			rawURL  string
			date    time.Time
			content []byte
		}
		want    http.Header
		wantErr error
	}{
		{
			name: "hmac authentication headers",
			input: struct {
				key     AccessKey
				method  string
				rawURL  string
				date    time.Time
				content []byte
			}{
				key: AccessKey{
					ID:     "id",
					Secret: base64.StdEncoding.EncodeToString([]byte("secret")),
				},
				method:  http.MethodGet,
				rawURL:  fmt.Sprintf("https://%s%s", _testHost, _testPathAndQuery),
				date:    _testDate,
				content: []byte(""),
			},
			want: http.Header{
				"X-Ms-Date":           []string{_testDateHttp},
				"Host":                []string{_testHost},
				"X-Ms-Content-Sha256": []string{_testHash},
				"Authorization":       []string{"HMAC-SHA256 Credential=id, SignedHeaders=x-ms-date;host;x-ms-content-sha256, Signature=" + _testSignature},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := http.Header{}
			gotErr := addHMACAuthenticationHeaders(got, test.input.key, test.input.method, test.input.rawURL, test.input.date, test.input.content)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("hmacAuthenticationHeaders() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors(), cmpopts.EquateApproxTime(5*time.Second)); diff != "" {
				t.Errorf("hmacAuthenticationHeaders() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestStringToSign(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			method       string
			pathAndQuery string
			date         string
			host         string
			contentHash  string
		}
		want string
	}{
		{
			name: "string to sign",
			input: struct {
				method       string
				pathAndQuery string
				date         string
				host         string
				contentHash  string
			}{
				method:       http.MethodGet,
				pathAndQuery: _testPathAndQuery,
				date:         _testDateHttp,
				host:         _testHost,
				contentHash:  _testHash,
			},
			want: "GET\n" + _testPathAndQuery + "\n" + _testDateHttp + ";" + _testHost + ";" + _testHash,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := stringToSign(test.input.method, test.input.pathAndQuery, test.input.date, test.input.host, test.input.contentHash)

			if test.want != got {
				t.Errorf("stringToSign() = unexpected result, want: %s, got: %s\n", test.want, got)
			}
		})
	}
}

func TestHash(t *testing.T) {
	want := "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	got, _ := hash([]byte(""))

	if want != got {
		t.Errorf("hash() = unexpected result, want: %s, got: %s\n", want, got)
	}
}

var (
	_testHash, _      = hash([]byte(""))
	_testHost         = "config.azconfig.io"
	_testPathAndQuery = "/kv/setting-a?api-version=1.0"
	_testDate         = time.Now().UTC()
	_testDateHttp     = _testDate.Format(http.TimeFormat)
	_testStringToSign = stringToSign(http.MethodGet, _testPathAndQuery, _testDateHttp, _testHost, _testHash)
	_testSecret       = base64.StdEncoding.EncodeToString([]byte("secret"))
	_testSignature, _ = sign(_testStringToSign, _testSecret)
)

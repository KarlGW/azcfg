package setting

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestHMACAuthenticationHeaders(t *testing.T) {
	oldNow := now
	now = func() time.Time {
		return time.Date(2024, 4, 27, 0, 0, 0, 0, time.UTC)
	}

	t.Cleanup(func() {
		now = oldNow
	})

	var tests = []struct {
		name  string
		input struct {
			key     AccessKey
			method  string
			rawURL  string
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
				content []byte
			}{
				key: AccessKey{
					ID:     "id",
					Secret: base64.StdEncoding.EncodeToString([]byte("secret")),
				},
				method:  "GET",
				rawURL:  "https://config.azconfig.io/kv/setting-a?api-version=1.0",
				content: []byte(""),
			},
			want: http.Header{
				"X-Ms-Date":           []string{now().UTC().Format(http.TimeFormat)},
				"Host":                []string{"config.azconfig.io"},
				"X-Ms-Content-Sha256": []string{_testHash},
				"Authorization":       []string{"HMAC-SHA256 Credential=id, SignedHeaders=x-ms-date;host;x-ms-content-sha256, Signature=oNlHsX/O8yP5gDTtb15L4U1KTYmGpnt1aKuIgfTeGZQ="},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := hmacAuthenticationHeaders(test.input.key, test.input.method, test.input.rawURL, test.input.content)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("hmacAuthenticationHeaders() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors(), cmpopts.EquateApproxTime(time.Second*5)); diff != "" {
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
				method:       "GET",
				pathAndQuery: "/kv/setting-a?api-version=1.0",
				date:         time.Date(2024, 4, 27, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat),
				host:         "config.azconfig.io",
				contentHash:  _testHash,
			},
			want: "GET\n/kv/setting-a?api-version=1.0\nSat, 27 Apr 2024 00:00:00 GMT;config.azconfig.io;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
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
	_testHash, _ = hash([]byte(""))
	//_testDate    = time.Now().Format(http.TimeFormat)
)

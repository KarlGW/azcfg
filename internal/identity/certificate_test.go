package identity

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/KarlGW/azcfg/internal/testutils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestCertificatesAndKeyFromPEM(t *testing.T) {
	var tests = []struct {
		name  string
		input []byte
		want  struct {
			certs []*x509.Certificate
			key   *rsa.PrivateKey
		}
		wantErr error
	}{
		{
			name:  "get certificates and key (PKCS8)",
			input: append(_testCert1.RawCert, _testCert1.RawKey...),
			want: struct {
				certs []*x509.Certificate
				key   *rsa.PrivateKey
			}{
				certs: []*x509.Certificate{_testCert1.Cert},
				key:   _testCert1.Key,
			},
		},
		{
			name:  "get certificates and key (PKCS1)",
			input: append(_testCert2.RawCert, _testCert2.RawKey...),
			want: struct {
				certs []*x509.Certificate
				key   *rsa.PrivateKey
			}{
				certs: []*x509.Certificate{_testCert2.Cert},
				key:   _testCert2.Key,
			},
		},
		{
			name:    "nil pem provided",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotCerts, gotKey, gotErr := CertificatesAndKeyFromPEM(test.input)

			if diff := cmp.Diff(test.want.certs, gotCerts); diff != "" {
				t.Errorf("CertificatesAndKeyFromPEM() = unexpected result (-want +got)\n%s\n", diff)
			}

			if test.want.key != nil && gotKey != nil {
				if diff := cmp.Diff(test.want.key, gotKey); diff != "" {
					t.Errorf("CertificatesAndKeyFromPEM() = unexpected result (-want +got)\n%s\n", diff)
				}
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("CertificatesAndKeyFromPEM() = unexpected result (-want +got)\n%s\n", diff)
			}
		})
	}
}

var (
	_testCert1, _ = testutils.CreateCertificate()
	_testCert2, _ = testutils.CreateCertificate(func(o *testutils.CreateCertificateOptions) {
		o.PKCS1 = true
	})
)

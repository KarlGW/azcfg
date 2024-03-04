package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// newClientAssertionJWT creates a new assertion jwt for a client credential.
func newClientAssertionJWT(tenantID, clientID string, cert certificate) (jwt, error) {
	header := header{
		ALG: "RS256",
		TYP: "JWT",
		X5T: cert.thumbprint,
	}
	if len(cert.x5c) > 0 {
		header.X5C = cert.x5c
	}

	uuid, err := newUUID()
	if err != nil {
		return jwt{}, err
	}

	claims := claims{
		AUD: "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/token",
		EXP: time.Now().Add(time.Minute * 5).Unix(),
		ISS: clientID,
		JTI: uuid,
		NBF: time.Now().Unix(),
		SUB: clientID,
		IAT: time.Now().Unix(),
	}

	t := jwt{
		header: header,
		claims: claims,
	}

	if err := t.sign(cert.key); err != nil {
		return jwt{}, err
	}

	return t, nil
}

// jwt is a JSON web token used for client credential with assertion.
type jwt struct {
	header    header
	signature signature
	claims    claims
}

// Encode returns the jwt as a string encoded for use in the request body.
func (t jwt) Encode() string {
	return t.header.Encode() + "." + t.claims.Encode() + "." + t.signature.Encode()
}

// sign the jwt with the private key.
func (t *jwt) sign(key *rsa.PrivateKey) error {
	data := []byte(t.header.Encode() + "." + t.claims.Encode())
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hashed[:])
	if err == nil {
		t.signature = signature
	}
	return err
}

// header is a JSON web token header.
type header struct {
	ALG string   `json:"alg"`
	TYP string   `json:"typ"`
	X5T string   `json:"x5t"`
	X5C []string `json:"x5c,omitempty"`
}

// Encode the header as a base64 encoded string.
func (h header) Encode() string {
	b, _ := json.Marshal(h)
	return base64.URLEncoding.EncodeToString(b)
}

// claims is a JSON web token claims.
type claims struct {
	AUD string `json:"aud"`
	ISS string `json:"iss"`
	JTI string `json:"jti"`
	SUB string `json:"sub"`
	EXP int64  `json:"exp"`
	NBF int64  `json:"nbf"`
	IAT int64  `json:"iat"`
}

// Encode the claims as a base64 encoded string.
func (c claims) Encode() string {
	b, _ := json.Marshal(c)
	return base64.URLEncoding.EncodeToString(b)
}

// signature is a JSON web token signature.
type signature []byte

// Encode the signature as a base64 encoded string.
func (s signature) Encode() string {
	return base64.URLEncoding.EncodeToString(s)
}

// newUUID creates a new UUID for the jwt.
var newUUID = func() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", err
	}

	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// certificate is a processed certificate chain and key that contains
// the main certificate, the private key, the thumbprint and
// the x5c chain.
type certificate struct {
	cert       *x509.Certificate
	key        *rsa.PrivateKey
	thumbprint string
	x5c        []string
}

// isZero returns true if certificate is empty.
func (c certificate) isZero() bool {
	return c.cert == nil && c.key == nil && len(c.thumbprint) == 0
}

// newCertificate processes the provided certificates and key and returns
// a certificate.
func newCertificate(certs []*x509.Certificate, key *rsa.PrivateKey) (certificate, error) {
	c := certificate{
		key: key,
	}
	if key == nil {
		return certificate{}, errors.New("private key is required")
	}

	for _, cert := range certs {
		if cert == nil {
			continue
		}
		ck, ok := cert.PublicKey.(*rsa.PublicKey)
		if ok && c.key.E == ck.E && c.key.N.Cmp(ck.N) == 0 {
			c.cert = cert
			hashed := sha1.Sum(c.cert.Raw)
			c.thumbprint = base64.StdEncoding.EncodeToString(hashed[:])
			c.x5c = append([]string{base64.StdEncoding.EncodeToString(cert.Raw)}, c.x5c...)

		} else {
			c.x5c = append(c.x5c, base64.StdEncoding.EncodeToString(cert.Raw))
		}
	}
	if c.cert == nil {
		return certificate{}, errors.New("provided certificates and key does not match")
	}

	return c, nil
}

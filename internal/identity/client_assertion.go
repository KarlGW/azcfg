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
	"fmt"
	"time"
)

// newClientAssertionJWT creates a new assertion jwt for a client credential.
func newClientAssertionJWT(tenantID, clientID string, certs []*x509.Certificate, key *rsa.PrivateKey) (jwt, error) {
	header := header{
		ALG: "RS256",
		TYP: "JWT",
		X5T: newX5T(certs[0].Raw),
		X5C: []string{},
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

	if err := t.sign(key); err != nil {
		return jwt{}, err
	}

	return t, nil
}

// jwt is a JSON web token used for client credential with assertion.
type jwt struct {
	header    header
	claims    claims
	signature signature
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
	EXP int64  `json:"exp"`
	ISS string `json:"iss"`
	JTI string `json:"jti"`
	NBF int64  `json:"nbf"`
	SUB string `json:"sub"`
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

// newX5T creates a new x5t thumbprint for the jwt.
func newX5T(der []byte) string {
	hashed := sha1.Sum(der)
	return base64.StdEncoding.EncodeToString(hashed[:])
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

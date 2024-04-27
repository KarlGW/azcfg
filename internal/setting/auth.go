package setting

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hmacAuthenticationHeaders returns the headers required for for Azure
// App Configuration authentication with access key.
func hmacAuthenticationHeaders(key AccessKey, method, rawURL string, content []byte) (http.Header, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	contentHash, err := hash(content)
	if err != nil {
		return nil, err
	}
	date := now().UTC().Format(http.TimeFormat)

	str := stringToSign(method, u.EscapedPath()+"?"+u.RawQuery, date, u.Host, contentHash)
	signature, err := sign(str, key.Secret)
	if err != nil {
		return nil, err
	}

	headers := http.Header{}
	headers.Add("X-Ms-Date", date)
	headers.Add("Host", u.Host)
	headers.Add("X-Ms-Content-Sha256", contentHash)
	headers.Add("Authorization", "HMAC-SHA256 Credential="+key.ID+", SignedHeaders=x-ms-date;host;x-ms-content-sha256, Signature="+signature)
	return headers, nil
}

// stringToSign return the string to sign for Azure App Configuration authentication
// with credential and key.
func stringToSign(method, pathAndQuery, date, host, contentHash string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteString("\n")
	b.WriteString(pathAndQuery)
	b.WriteString("\n")
	b.WriteString(date)
	b.WriteString(";")
	b.WriteString(host)
	b.WriteString(";")
	b.WriteString(contentHash)
	return b.String()
}

// sign the string with the secret key using HMAC-SHA256 and
// return the base64 encoded string.
func sign(stringToSign, secret string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	hmac := hmac.New(sha256.New, []byte(key))
	_, err = hmac.Write([]byte(stringToSign))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hmac.Sum(nil)), nil
}

// hash the provided content using SHA256 and return the base64
// encoded string.
func hash(content []byte) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write(content)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}

var now = time.Now

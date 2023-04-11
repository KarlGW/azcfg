package azcfg

import (
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

var (
	// defaultConcurrency contains the default concurrency for the
	// parser.
	defaultConcurrency = 10
	// defaultTimeout contains the default timeout for the parser.
	defaultTimeout = time.Millisecond * 1000 * 10
)

var (
	// parser is the package level parser and the settings.
	parser = Parser{
		secrets:     secrets{},
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
	}
)

// secrets contains options for the secrets client.
type secrets struct {
	client     SecretsClient
	credential azcore.TokenCredential
	vault      string
}

// Parser ...
type Parser struct {
	secrets     secrets
	timeout     time.Duration
	concurrency int
}

// Options ...
type Options struct {
	SecretsClient SecretsClient
	Credential    azcore.TokenCredential
	Vault         string
	Timeout       time.Duration
	Concurrency   int
}

// NewParser creates and returns a *Parser.
func NewParser(options ...Options) *Parser {
	parser := &Parser{
		timeout:     defaultTimeout,
		concurrency: defaultConcurrency,
	}
	for _, o := range options {
		if o.SecretsClient != nil {
			parser.secrets.client = o.SecretsClient
		}
		if o.Credential != nil {
			parser.secrets.credential = o.Credential
		}
		if len(o.Vault) != 0 {
			parser.secrets.vault = o.Vault
		}
		if o.Timeout != 0 {
			parser.timeout = o.Timeout
		}
		if o.Concurrency != 0 {
			parser.concurrency = o.Concurrency
		}
	}
	return parser
}

// Parse secrets from an Azure Key Vault into a struct.
func (p Parser) Parse(v any) error {
	return parse(v, p.secrets.client)
}

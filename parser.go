package azcfg

import (
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// Client is the interface that wraps around method GetSecrets.
type Client interface {
	GetSecrets(names []string) (map[string]string, error)
}

// Parser contains all the necessary values and settings for calls to Parse.
type Parser struct {
	client      Client
	credential  azcore.TokenCredential
	vault       string
	timeout     time.Duration
	concurrency int
}

// NewParser creates and returns a *Parser. With no options provided
// it will have default settings for timeout and concurrency.
func NewParser(options ...Options) *Parser {
	p := &Parser{
		timeout:     defaultTimeout,
		concurrency: defaultConcurrency,
	}
	return evalOptions(p, options...)
}

// Parse secrets from an Azure Key Vault into a struct.
func (p *Parser) Parse(v any, options ...Options) error {
	var err error
	p, err = evalClient(evalOptions(p, options...), newAzureCredential, newKeyvaultClient)
	if err != nil {
		return err
	}
	return parse(v, p.client)
}

// SetClient sets an alternative client for Azure Key Vault requests.
// Must implement Client.
func (p *Parser) SetClient(client Client) *Parser {
	p.client = client
	return p
}

// SetCredential sets credential to be used for requests to Azure Key Vault.
// Use when credential reuse is desirable.
func (p *Parser) SetCredential(cred azcore.TokenCredential) *Parser {
	p.credential = cred
	p.client = nil
	return p
}

// SetVault sets the Azure Key Vault to query for secrets.
func (p *Parser) SetVault(vault string) *Parser {
	p.vault = vault
	p.client = nil
	return p
}

// SetConcurrency sets amount of concurrent calls for fetching secrets.
func (p *Parser) SetConcurrency(c int) *Parser {
	p.concurrency = c
	p.client = nil
	return p
}

// SetTimeout sets the total timeout for the requests for fetching secrets.
func (p *Parser) SetTimeout(d time.Duration) *Parser {
	p.timeout = d
	p.client = nil
	return p
}

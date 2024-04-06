package identity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/KarlGW/azcfg/auth"
)

var (
	// ErrAzureCLINotFound is returned when the Azure CLI is not found.
	ErrAzureCLINotFound = errors.New("azure cli not found")
)

// AzureCLICredential represent credentials handled by the Azure CLI. It
// contains all the necessary settings to perform token requests.
type AzureCLICredential struct {
	tokens map[auth.Scope]*auth.Token
	mu     sync.RWMutex
}

// NewAzureCLICredential creates and returns a new *AzureCLICredential.
func NewAzureCLICredential(options ...CredentialOption) (*AzureCLICredential, error) {
	c := &AzureCLICredential{
		tokens: make(map[auth.Scope]*auth.Token),
	}

	opts := CredentialOptions{}
	for _, option := range options {
		option(&opts)
	}

	return c, nil
}

// Token returns a new auth.Token for requests to the Azure REST API.
func (c *AzureCLICredential) Token(ctx context.Context, options ...auth.TokenOption) (auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	opts := auth.TokenOptions{
		Scope: auth.ScopeResourceManager,
	}
	for _, option := range options {
		option(&opts)
	}

	if c.tokens[opts.Scope] != nil && c.tokens[opts.Scope].ExpiresOn.UTC().After(time.Now().UTC()) {
		return *c.tokens[opts.Scope], nil
	}

	token, err := cliToken(ctx, string(opts.Scope))
	if err != nil {
		return auth.Token{}, err
	}

	c.tokens[opts.Scope] = &token
	return *c.tokens[opts.Scope], nil
}

// cliToken requests a token after creating the request body
// based on the settings of the ClientCredential.
var cliToken = func(ctx context.Context, scope string) (auth.Token, error) {
	var command, flag, dir string
	if runtime.GOOS == "windows" {
		dir = os.Getenv("SYSTEMROOT")
		command = "cmd.exe"
		flag = "/c"
	} else {
		dir = "/bin"
		command = "/bin/sh"
		flag = "-c"
	}

	arguments := "az account get-access-token --output json --resource " + strings.TrimSuffix(scope, "/.default")
	cmd := exec.CommandContext(ctx, command, flag, arguments)
	cmd.Dir = dir
	cmd.Env = os.Environ()

	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 127 || strings.HasPrefix(string(exitErr.Stderr), "'az' is not recognized") {
			return auth.Token{}, ErrAzureCLINotFound
		}
		return auth.Token{}, err
	}

	var r cliAuthResult
	if err := json.Unmarshal(output, &r); err != nil {
		return auth.Token{}, err
	}

	return auth.Token{
		AccessToken: r.AccessToken,
		ExpiresOn:   time.Unix(int64(r.ExpiresOn), 0),
	}, nil
}

// cliAuthResult represents a token response from the Azure CLI.
type cliAuthResult struct {
	AccessToken string  `json:"accessToken"`
	ExpiresOn   float64 `json:"expires_on"`
}

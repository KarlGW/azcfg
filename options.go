package azcfg

import (
	"errors"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// envKeyVault contains environment variables to check for
// Azure Key Vault name.
var (
	envKeyVault = []string{
		"AZURE_KEY_VAULT",
		"AZURE_KEY_VAULT_NAME",
		"AZURE_KEYVAULT",
		"AZURE_KEYVAULT_NAME",
	}
)

// opts sets and contains options for the package.
var (
	opts = &options{
		Credential: nil,
		Vault:      "",
	}
)

// options contains options for the package.
type options struct {
	Credential azcore.TokenCredential
	Vault      string
}

// SetCredentials sets credentials to be used for requests to Azure Key Vault.
// Use when credential reuse is desireable.
func SetCredential(cred azcore.TokenCredential) {
	opts.Credential = cred
}

// SetVault sets the Azure Key Vault to query for
// secrets.
func SetVault(vault string) {
	opts.Vault = vault
}

// getVault checks the environment if any of the variables AZURE_KEY_VAULT,
// AZURE_KEY_VAULT_NAME, AZURE_KEYVAULT or AZURE_KEYVAULT_NAME is set.
func getVaultFromEnvironment() (string, error) {
	for _, v := range envKeyVault {
		if len(os.Getenv(v)) != 0 {
			return os.Getenv(v), nil
		}
	}
	return "", errors.New("a Key Vault name must be set")
}

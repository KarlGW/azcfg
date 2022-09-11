# azcfg

> Set Azure Key Vault secrets to a configuration

* [Getting started](#getting-started)
  * [Install](#install)
  * [Prerequisites](#prerequisistes)
  * [Example](#example)

## Getting started

### Install

```
go get github.com/KarlGW/azcfg
```

### Prerequisites

* Azure Key Vault
  * Identity with access to secrets in the Key Vault


**Service Principal**

Environment variables:

* `AZURE_TENANT_ID` - Tenant ID of the service principal/application registration.
* `AZURE_CLIENT_ID` - Client ID (also called Application ID) of the service principal/application registration.
* `AZURE_CLIENT_SECRET` - Client Secret of the service principal/application registration.
* `AZURE_KEY_VAULT`/`AZURE_KEY_VAULT_NAME`/`AZURE_KEYVAULT`/`AZURE_KEYVAULT_NAME` - Name of the Azure Key Vault.

**Managed Identity (User assigned)**

Environment variables:

* `AZURE_CLIENT_ID` - Client ID (also called Application ID) of the Managed Identity.
* `AZURE_KEY_VAULT`/`AZURE_KEY_VAULT_NAME`/`AZURE_KEYVAULT`/`AZURE_KEYVAULT_NAME` - Name of the Azure Key Vault.

**Managed Identity (System assigned)**

Environment variables:

* `AZURE_KEY_VAULT`/`AZURE_KEY_VAULT_NAME`/`AZURE_KEYVAULT`/`AZURE_KEYVAULT_NAME` - Name of the Azure Key Vault.

**Setting options**

Instead of setting environment variables options can be set on the module level.

```go
// Setting credential. See example for supported credential types and how to set the at:
// https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#readme-credential-types.
// This is useful when the same credentials should be used through the entire application,
// the default is that the module uses it's own instance and set of credentials.
cred, err := azidentity.<FunctionForCredentialType>
if err != nil {
    // Handle error.
}
azcfg.SetCredential(cred)

// Setting Key Vault name.
azcfg.SetVault("vaultname")
```

### Example

```go
package main

type config struct {
    Host string
    Port int
    
    Username string `secret:"user-name"`
    Password string `secret:"password"`

    SubConfig subConfig
}

type subConfig struct {
    Key int `secret:"key"`
}

func main() {
    cfg := config{}
    if err := azcfg.Parse(&cfg); err != nil {
        // Handle error.
    }

    fmt.Printf("%+v", cfg)
}
```
# azcfg

> Set Azure Key Vault secrets to a struct

* [Getting started](#getting-started)
  * [Install](#install)
  * [Prerequisites](#prerequisites)
  * [Example](#example)

This library is used to get secrets from an Azure Key Vault and set them into a struct. The idea on usage
was inspired by [`env`](https://github.com/caarlos0/env).

To mark a field in a struct to be populated by a secret set the struct tag `secret` followed by the name
of the secret in Azure Key Vault, like so:
```
`secret:"<secret-name>"`
```
Nested structs and pointers are supported.

See [example](#example) for more.

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

* `AZURE_KEY_VAULT`/`AZURE_KEY_VAULT_NAME`/`AZURE_KEYVAULT`/`AZURE_KEYVAULT_NAME` - Name of the Azure Key Vault.
* `AZURE_TENANT_ID` - Tenant ID of the service principal/application registration.
* `AZURE_CLIENT_ID` - Client ID (also called Application ID) of the service principal/application registration.

Using client secret:
* `AZURE_CLIENT_SECRET` - Client Secret of the service principal/application registration.

Using certificate:
* `AZURE_CLIENT_CERTIFICATE_PATH` - Path to certificate for the service principal/application registration.


**Managed Identity (User assigned)**

Environment variables:

* `AZURE_KEY_VAULT`/`AZURE_KEY_VAULT_NAME`/`AZURE_KEYVAULT`/`AZURE_KEYVAULT_NAME` - Name of the Azure Key Vault.
* `AZURE_CLIENT_ID` - Client ID (also called Application ID) of the Managed Identity.

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

// Set the Key Vault client credential:
azcfg.SetCredential(cred)
// Setting Key Vault name:
azcfg.SetVault("vault-name")
// Setting Key Vault client concurrent calls (defaults to 10):
azcfg.SetConcurrency(20)
// Setting Key Vault client timeout for the total amount of requests (default to 10 seconds):
azcfg.SetTimeout(time.Millsecond * 1000 * 20)
// Setting the entire client options:
azcfg.SetClientOptions(&azcfg.ClientOptions{
    Credential: cred,       // Defaults to nil, the built-in credential auth.
    Vault: "vault-name",    // Defaults to "" (empty string), which will check environment variables.
    Concurrency: 20,        // Defaults to 10.
    Timeout: duration,      // Defaults to time.Millisecond * 1000 * 10 (10 seconds)
})
```

### Example

```go
package main

type config struct {
    Host string
    Port int
    
    Username string `secret:"username"`
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

**Supported types**

* `string`
* `bool`
* `int`
* `int8`
* `int16`
* `int32`
* `int64`
* `float32`
* `float64`

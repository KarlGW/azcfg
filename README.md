# azcfg

[![Go Reference](https://pkg.go.dev/badge/github.com/KarlGW/azcfg.svg)](https://pkg.go.dev/github.com/KarlGW/azcfg)

> Azure Confidential Field Gatherer - Set Azure Key Vault secrets to a struct

* [Getting started](#getting-started)
  * [Install](#install)
  * [Prerequisites](#prerequisites)
  * [Example](#example)
* [Usage](#usage)
  * [Options](#options)
  * [Required](#required)

This library is used to get secrets from an Azure Key Vault and set them into a struct. The idea of parsing
configuration values into a struct was inspired by [`env`](https://github.com/caarlos0/env).

To mark a field in a struct to be populated by a secret set the struct tag `secret` followed by the name
of the secret in Azure Key Vault, like so:
```
`secret:"<secret-name>"`
```

If the secret does not exist the field will keep the value it had prior to the call to `Parse`.


The secret can be marked as required, this will make the call to `Parse` return an error if the secret
does not exist:

```
secret:"<secret-name>,required"
```

The error message contains all fields that have been marked as required that didn't have a secret associated with them.

**Note**: Unexported fields will be ignored.

See [example](#example) for more.

## Getting started

### Install

```
go get github.com/KarlGW/azcfg
```

### Prerequisites

* Go 1.18
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

### Example

```go
package main

type config struct {
    Host string
    Port int

    Username string `secret:"username"`
    Password string `secret:"password"`

    Credential credential
}

type credential struct {
    Key int `secret:"key"`
}

func main() {
    cfg := config{}
    if err := azcfg.Parse(&cfg); err != nil {
        // Handle error.
    }

    fmt.Printf("%+v\n", cfg)
}
```

```sh
{Host: Port:0 Username:username-from-keyvault Password:password-from-keyvault Credential:{Key:12345}}
```

It is possible to pass options to `Parse` that will override the package options for that particular call:

```go
package main

func main() {
    cfg := config{}
    if err := azcfg.Parse(&cfg, &azcfg.Options{
        Client: client,
        Credential: cred,
        Vault: "vault",
        Concurrency: 20,
        Timeout: time.Millisecond * 1000 * 20
    }); err != nil {
        // Handle error.
    }
}
```

An independent `Parser` can be created and passed around inside of the application.

```go
package main

func main() {
    parser := azcfg.NewParser()

    cfg := config{}
    if err := parser.Parse(&cfg); err != nil {
        // Handle error.
    }
}
```

Both the `NewParser` and the `Parse` method on the `Parser` supports `Options` as in the examples
for the package level `Parse` function.

```go
package main

func main() {
    parser := azcfg.NewParser(azcfg.Options{})

    cfg := config{}
    if err := parser.Parse(azcfg.Options{}); err != nil {
        // Handle error.
    }
}
```

For supported options see `Options` struct.

## Usage

**Supported types**

* `string`
* `bool`
* `uint`, `uint8`, `uint16`, `uint32`, `uint64`
* `int`, `int8`, `int16`, `int32`, `int64`
* `float32`, `float64`


### Options

The behaviour of the module can be modified with the help of various options.

```go
// Setting options for the package:
azcfg.SetOptions(&azcfg.Options{
    Client: client,         // Defaults to nil, the built-in secrets client.
    Credential: cred,       // Defaults to nil, the built-in Azure credential authentication flow.
    Vault: "vault"          // Defaults to "", which will check environment variables.
    Concurrency: 20,        // Defaults to 10.
    Timeout: duration,      // Defaults to time.Millisecond * 1000 * 10 (10 seconds)
})


// Setting a client for Azure Key Vault. Provided client must implement
// Client. Useful for stubbing dependencies when testing applications
// using this library.
azcfg.SetClient(client)


// Setting credential. See example for supported credential types and how to set the at:
// https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#readme-credential-types.
// This is useful when the same credentials should be used through the entire application,
// the default is that the module uses it's own instance and set of credentials.
cred, err := azidentity.<FunctionForCredentialType>
if err != nil {
    // Handle error.
}
azcfg.SetCredential(cred)


// Setting secrets vault name:
azcfg.SetVault("vault")


// Setting concurrent calls for the client (defaults to 10):
azcfg.SetConcurrency(20)


// Setting timeout for the total amount of requests (default to 10 seconds):
azcfg.SetTimeout(time.Millsecond * 1000 * 20)


// The "Set"-functions are chainable (with the exception of SetOptions), and can be called like so:
azcfg.SetConcurrency(20).SetTimeout(time.Millisecond * 1000 * 10)
```

### Required

The default behaviour of `Parse` is to ignore secrets that does not exist and let the field contain it's original value.
To enforce secrets to be set the option `required` can be used.

```go
type Example struct {
    FieldA `secret:"field-a"`
    FieldB `secret:"field-b,required"`
}
```

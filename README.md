# azcfg

[![Go Reference](https://pkg.go.dev/badge/github.com/KarlGW/azcfg.svg)](https://pkg.go.dev/github.com/KarlGW/azcfg)

> Azure Config - Set Azure Key Vault secrets and Azure App Config settings to a struct

* [Getting started](#getting-started)
  * [Install](#install)
  * [Prerequisites](#prerequisites)
  * [Example](#example)
* [Usage](#usage)
  * [Options](#options)
  * [Required](#required)
  * [Parser](#parser)
  * [Pre-populated struct and default values](#pre-populated-struct-and-default-values)
  * [Timeout and context](#timeout-and-context)
  * [App Configuration setting labels](#app-configuration-setting-labels)
  * [Authentication](#authentication)
    * [Built-in credentials](#built-in-credentials)
      * [Authentication with environment variables](#authentication-with-environment-variables)
      * [Authentication with options](#authentication-with-options)
      * [App Configuration with access key or connection string](#app-configuration-with-access-key-or-connection-string)
  * [Credentials](#credentials)
  * [National clouds](#national-clouds)

This module is used to get secrets from an Azure Key Vault and settings from App Configuraion and set them into a struct. The idea of parsing
configuration values into a struct was inspired by [`env`](https://github.com/caarlos0/env).

It is not required to have a Key Vault if not parsing secrets, and it is not required to have an App Configuration if not parsing settings.

To mark a field in a struct to be populated by a secret set the struct tag `secret` followed by the name
of the secret in Azure Key Vault, like so:
```
`secret:"<secret-name>"`
```

To mark a field i a struct to be populated by a setting set the struct tag `setting` followed by the name
of the setting in Azure App Configuration, like so:
```
`setting:"<setting-name>"`
```

If the secret or setting does not exist the field will keep the value it had prior to the call to `Parse`.


The secret and setting can be marked as required, this will make the call to `Parse` return an error if the they
do not exist:

```
secret:"<secret-name>,required"
setting:"<setting-name>,required"
```

The error message contains all fields that have been marked as required that didn't have a value associated with them.

**Note**: Unexported fields will be ignored.

## Getting started

### Install

```
go get github.com/KarlGW/azcfg
```

### Prerequisites

* Go 1.18
* Azure Key Vault (if using secrets)
  * Identity with access to secrets in the Key Vault
* Azure App Configuration (is using settings and configuration)
  * Identity with access to the App Configuration (if not using access key or connection string)


### Example

Using a managed identity as credentials on an Azure service. For other authentication and credential methods see the sections [Authentication](#authentication) and [Credentials](#credentials).

### Example with secrets (Key Vault)

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

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

### Example with settings (App Configuration)

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

type config struct {
    Host string
    Port int

    Username string `setting:"username"`
    Password string `setting:"password"`

    Credential credential
}

type credential struct {
    Key int `setting:"key"`
}

func main() {
    var cfg config
    if err := azcfg.Parse(&cfg); err != nil {
        // Handle error.
    }

    fmt.Printf("%+v\n", cfg)
}
```

```sh
{Host: Port:0 Username:username-from-appconfig Password:password-from-appconfig Credential:{Key:12345}}
```

### Example using both secrets (Key Vault) and settings (App Configuration)

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

type config struct {
    Host string
    Port int

    Username string `setting:"username"`
    Password string `setting:"password"`

    Credential credential
}

type credential struct {
    Key int `secret:"key"`
}

func main() {
    var cfg config
    if err := azcfg.Parse(&cfg); err != nil {
        // Handle error.
    }

    fmt.Printf("%+v\n", cfg)
}
```

```sh
{Host: Port:0 Username:username-from-appconfig Password:password-from-appconfig Credential:{Key:12345}}
```

## Usage

**Supported types**

* `string`
* `bool`
* `uint`, `uint8`, `uint16`, `uint32`, `uint64`
* `int`, `int8`, `int16`, `int32`, `int64`
* `float32`, `float64`
* `complex64`, `complex128`
* `time.Duration`

**Note**: Pointers to the above types are supported.

Slices are supported if the secret/setting are comma separated values (spaces are trimmed by the parser).

**Strings**

`value1,value2,value3`

**Numbers**
`1,2,3`


### Options

Options can be provided to `Parse` or `NewParser`:

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

func main() {
    var cfg config
    if err := azcfg.Parse(&cfg, func(o *Options) {
        o.Credential = cred
        o.KeyVault = "vault"
        o.AppConfiguration = "appconfig"
        o.Concurrency = 20
        o.Timeout = time.Millisecond * 1000 * 20
    }); err != nil {
        // Handle error.
    }
}
```

Option functions are provided by the module for convenience, see [Option](https://pkg.go.dev/github.com/KarlGW/azcfg#Option).

When providing options to the `Parse` method on a `Parser`,
only `WithContext` is valid.

### Required

The default behaviour of `Parse` is to ignore secrets and settings that does not exist and let the field contain it's original value.
To enforce fields to be set the option `required` can be used.

```go
type Example struct {
    FieldA `secret:"field-a"`
    FieldB `secret:"field-b,required"`
    FieldC `setting:"field-c,required"`
}
```
If a `required` secret or setting doesn't exist in the Key Vault an error will be returned. The error message contains all
fields that have been marked as required that didn't have a secret or setting associated with them.

### Parser

An independent `parser` can be created and passed around inside of the application.

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

func main() {
    parser, err := azcfg.NewParser()
    if err != nil {
        // Handle error.
    }

    var cfg config
    if err := parser.Parse(&cfg); err != nil {
        // Handle error.
    }
}
```

The constructor function `NewParser` supports the same options as the module level `Parse` function.
For supported options see [`Options`](https://pkg.go.dev/github.com/KarlGW/azcfg#Options) struct or list of function options in the [Options](#options) section.

### Pre-populated struct and default values

A struct can be set with values prior to parsing. This is useful if not all fields should be handled by the parser, or default values should
be set on the struct (in this case tag `,required` should not be set on the field).

If the values for fields that are tagged are retrived, they will overwrite the current values.

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

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
    cfg := config{
        Host: "localhost",
        Port: 8080
        Username: os.Getenv("USERNAME")
        Password: os.Getenv("PASSWORD")
    }


    if err := azcfg.Parse(&cfg); err != nil {
        // Handle error.
    }

    fmt.Printf("%+v\n", cfg)
}
```

### Timeout and context

By default the `Parse` function and `Parse` method on `Parser` creates a `context` with the configured (or default) timeout.
For those cases that a custom `context` is desired, it can be passed with an option to `Parse`:

#### With `Parse`

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), time.Second * 30)
    defer cancel()

    var cfg Config
    if err := azcfg.Parse(&cfg, azcfg.WithContext(ctx)); err != nil {
        // Handle error.
    }
}
```

#### With `Parser`

```go
package main

import (
    "github.com/KarlGW/azcfg"
)

func main() {
    parser, err := azcfg.NewParser()
    if err != nil {
        // Handle error.
    }

    ctx, cancel := context.WithTimeout(context.Background(), time.Second * 30)
    defer cancel()

    var cfg Config
    if err := parser.Parse(&cfg, azcfg.WithContext(ctx)); err != nil {
        // Handle error.
    }
}
```

### App Configuration setting labels

Settings in App Configuration can have labels associated with them.

To target a specific label for all settings:

- Set the label to the environment variable `AZCFG_APPCONFIGURATION_LABEL`.
- Use the option function `WithLabel`.

To target speciefic settings with specific labels:

- Set the labels to the environment variable `AZCFG_APPCONFIGURATION_LABELS` with format: `setting1=label1,setting2=label2`.
- Use the option function `WithLabels` and provide a `map[string]string` with the setting as key and label as value.

### Authentication

The module supports several ways of authenticating to Azure and get secrets from the target Key Vault and settings from the target App Configuration.

1. Built-in credentials that supports Service Principal (Client Credentials with secret, certificate or an assertion),
managed identity (system and user assigned) and Azure CLI. These provide in-memory caching of tokens to handle repeat calls.
2. Credentials from [`azidentity`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity) with the submodule [`authopts`](./authopts/)
3. Custom credential handling by implementing the `auth.Credential` interface.

For more information about option **2** and **3**, see [Credentials](#credentials).

#### Built-in credentials

##### Authentication with environment variables

For all authentication scenarios the following environment variables are used:

* `AZCFG_KEYVAULT_NAME` - Name of the Azure Key Vault (if using secrets).
* `AZCFG_APPCONFIGURATION_NAME` - Name of the Azure App Configuration (if using settings).

**Service Principal (client credentials with secret)**

* `AZCFG_TENANT_ID` - Tenant ID of the service principal/application registration.
* `AZCFG_CLIENT_ID` - Client ID (also called Application ID) of the service principal/application registration.
* `AZCFG_CLIENT_SECRET`- Client Secret of the service principal/application registration.

**Service Principal (client credentials with certificate)**

* `AZCFG_TENANT_ID` - Tenant ID of the service principal/application registration.
* `AZCFG_CLIENT_ID` - Client ID (also called Application ID) of the service principal/application registration.
* `AZCFG_CLIENT_CERTIFICATE` - Base64 encoded certificate (PEM).
* `AZCFG_CLIENT_CERTIFICATE_PATH` - Path to certificate (PEM).

**Managed identity**

* `AZCFG_CLIENT_ID` - (Optional) Client ID (also called Application ID) of the Managed Identity. Set if using a user assigned managed identity.

**Azure CLI**

* `AZCFG_AZURE_CLI_CREDENTIAL`

Requires Azure CLI to be installed, and being logged in.

```sh
# Login to Azure.
az login
# Set subscription where Key Vault is provisioned.
az account set --subscription <subscription-id>
```

##### Authentication with options

If more control is needed, such as custom environment variables or other means of getting the necessary values, options can be used.
Provided options will override values set from environment variables.

**Service Principal**

```go
// Client Secret.
azcfg.Parse(
    &cfg,
    azcfg.WithClientSecretCredential(tenantID, clientID, clientSecret),
    azcfg.WithKeyVault(vault),
)

// Client certificate.
azcfg.Parse(
    &cfg,
    azcfg.WithClientCertificateCredential(tenantID, clientID, certificates, key),
    azcfg.WithKeyVault(vault),
)

// Client assertion/federated credentials.
azcfg.Parse(
    &cfg,
    azcfg.WithClientAssertionCredential(tenantID, clientID, func() (string, error) {
	    return "assertion", nil
    }),
    azcfg.WithKeyVault(vault),
)
```

**Managed identity**

```go
// System assigned identity.
azcfg.Parse(&cfg, azcfg.WithManagedIdentity(), azcfg.WithKeyVault(vault))
// User assigned identity.
azcfg.Parse(&cfg, azcfg.WithManagedIdentity(), azcfg.WithClientID(clientID), azcfg.WithKeyVault(vault))
```

**Azure CLI**

```go
azcfg.Parse(&cfg, azcfg.WithAzureCLICredential(), azcfg.WithKeyVault(vault))
```

**Note**: Azure CLI credentials are best suited for development.


**Other**

To use a credential provided from elsewhere, such as the `azidentity` module see the section about
[Credentials](#credentials).

#### App Configuration with access key or connection string

In addition to using a managed identity or a service principal (the recommended methods) to access
an app configuration, it supports the use of an access key or connection string. If one of these
are provided, they will take precedence over the identity credential.

**Access key**

Either use environment variables:

* `AZCFG_APPCONFIGURATION_ACCESS_KEY_ID` - ID of the access key.
* `AZCFG_APPCONFIGURATION_ACCESS_KEY_SECRET` - Secret of the access key.

Or provide an option:

```go
azcfg.Parse(&cfg, azcfg.WithAppConfigurationAccessKey(accessKeyID, accessKeySecret))
```

**Connection string**

The connection string has the following format:

```
Endpoint=https://{appConfiguration}.azconfig.io;Id={accessKeyID};Secret={accessKeySecret}
```

Either use an environment variable:

* `AZCFG_APPCONFIGURATION_CONNECTION_STRING`

Or provide an option:

```go
azcfg.Parse(&cfg, azcfg.WithAppConfigurationConnectionString(connectionString))
```

### Credentials

Custom credentials with token retrieval can be used using the option `WithCredential`. They must satisfy the interface `Credential`:

```go
// Credential is the interface that wraps around method Token, Scope
// and SetScope.
type Credential interface {
	Token(ctx context.Context, options ...TokenOption) (Token, error)
}
```

**Note**: It is up to the provided implementation to cache tokens if needed.

Since it is reasonable to assume that credentials retrieved with the help of the `azidentity` module might need to be used, a submodule, [`authopts`](./authopts/) is provided. This make it easier to reuse credentials from `azidentity`.

**Usage**
```sh
go get github.com/KarlGW/azcfg/authopts
```

```go
package main

import (
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/KarlGW/azcfg"
    "github.com/KarlGW/azcfg/authopts"
)

func main() {
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        // Handle error.
    }

    var cfg config
    if err := azcfg.Parse(&cfg, authopts.WithTokenCredential(cred)); err != nil {
        // Handle error.
    }
}
```

**Note** Like the default credential implementations, in-memory token
caching is provided for repeat calls.

For additional information about how to use `azidentity`, check its [documentation](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity).


### National clouds

By default the standard Azure (Public Cloud) is the target for all requests. By either setting an option or an environment variable others
can be used.

The following are supported:

- Azure Public (the standard Azure cloud)
- Azure Government
- Azure China

**With options**

```go
package main

import (
    "github.com/KarlGW/azcfg"
    "github.com/KarlGW/azcfg/azure/cloud"
)

func main() {
    var cfg Config
    // Azure Public (is default, but for the case of the example).
    if err := azcfg.Parse(&cfg, azcfg.WithCloud(cloud.AzurePublic)); err != nil {
        // Handle error.
    }

    // Azure Government.
    if err := azcfg.Parse(&cfg, azcfg.WithCloud(cloud.AzureGovernment)); err != nil {
        // Handle error.
    }

    // Azure China.
    if err := azcfg.Parse(&cfg, azcfg.WithCloud(cloud.AzureChina)); err != nil {
        // Handle error.
    }

    // Parser.
    parser, err := azcfg.NewParser(azcfg.WithCloud(cloud.AzurePublic))
    if err != nil {
        // Handle error.
    }
}
```

**With environment variable**

Set the environment variable `AZCFG_CLOUD`.

- **Azure Public**: `Azure`, `Public` or `AzurePublic`.
- **Azure Government**: `Government` or `AzureGovernment`.
- **Azure China**: `China` or `AzureChina`.

**Note**: Case insensitive.

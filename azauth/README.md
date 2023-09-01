# azauth

> Extension to `azcfg` with option to use `azcore.TokenCredential`

This module is an extension to `azcfg` that exposes a single function, `WithTokenCredential` that
takes an `azcore.TokenCredential` and sets it to the parser.

## Usage

```sh
go get github.com/KarlGW/azcfg
go get github.com/KarlGW/azcfg/azauth
```

```go
package main

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/KarlGW/azcfg"
	"github.com/KarlGW/azcfg/azauth"
)

func main() {
    // Create a credential with the azidentity module. Any of the credential
    // types that satisfies azcore.TokenCredential will do.
    cred, err := azidentity.NewDefaultAzureCredential()
    if err != nil {
        // Handle error.
    }

    // When parsing.
    if err := azcfg.Parse(&cfg, azauth.WithTokenCredential(cred)); err != nil {
        // Handle error.
    }
    // When creating a new parser.
    parser := azcfg.NewParser(azauth.WithTokenCredential(cred))
    if err := parser.Parse(&cfg); err != nil {
        // Handle error.
    }
}
```

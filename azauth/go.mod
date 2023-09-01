module github.com/KarlGW/azcfg/azauth

go 1.21.0

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.7.1
	github.com/KarlGW/azcfg v0.0.0-00010101000000-000000000000
	github.com/google/go-cmp v0.5.9
)

replace github.com/KarlGW/azcfg => ../

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.3.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/text v0.8.0 // indirect
)

package cloud

// Cloud represents an Azure cloud.
type Cloud string

const (
	// AzurePublic is the public Azure cloud.
	AzurePublic Cloud = "AzurePublic"
	// AzureGovernment is the Azure Government cloud.
	AzureGovernment Cloud = "AzureGovernment"
	// AzureChina is the Azure China cloud.
	AzureChina Cloud = "AzureChina"
)

package cloud

// Cloud represents an Azure cloud.
type Cloud string

// Valid returns true if the cloud is a valid Azure cloud.
func (c Cloud) Valid() bool {
	switch c {
	case AzurePublic, AzureGovernment, AzureChina:
		return true
	}
	return false
}

const (
	// AzurePublic is the public Azure cloud.
	AzurePublic Cloud = "AzurePublic"
	// AzureGovernment is the Azure Government cloud.
	AzureGovernment Cloud = "AzureGovernment"
	// AzureChina is the Azure China cloud.
	AzureChina Cloud = "AzureChina"
)

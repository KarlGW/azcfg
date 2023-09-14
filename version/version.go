package version

var (
	// version contains version of azcfg.
	version = ""
	// commit contains commit hash of azcfg.
	commit = ""
)

// Version returns the version of azcfg.
func Version() string {
	return version
}

// Commit returns the commit hash of azcfg.
func Commit() string {
	return commit
}

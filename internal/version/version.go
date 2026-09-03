package version

import "fmt"

const (
	// Version is the human-chosen major.minor release version.
	Version = "v1.0"

	// Build is the sequential build identifier, updated on code commits.
	Build = "0031"
)

// Full returns the formatted version string, e.g. "v1.0 build(0001)".
func Full() string {
	return fmt.Sprintf("%s build(%s)", Version, Build)
}

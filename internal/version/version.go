package version

import (
	"fmt"
	"runtime"
)

// Set via ldflags at build time.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func String() string {
	return fmt.Sprintf("%s (%s, %s)", Version, Commit, BuildDate)
}

func GoVersion() string {
	return runtime.Version()
}

func Platform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

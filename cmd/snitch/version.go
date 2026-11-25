// version.go: the build's version, the same shape as snitchd's. Nothing here touches the
// daemon or the kernel; it only prints.
package main

import (
	"fmt"
	"io"

	"github.com/norandom/snitch/internal/contract"
)

// version is the build: set at link time by -ldflags "-X main.version=vX.Y.Z" (the release
// workflow), "dev" for a plain go build or go run. Printed by -version.
var version = "dev"

// printVersion is the -version answer: the version and a newline.
func printVersion(w io.Writer, v string) { _, _ = fmt.Fprintln(w, mustVersion(v)) }

// mustVersion is the one place the version is read for output: a link with an empty value
// (-X main.version=) would otherwise print an empty line.
func mustVersion(v string) string {
	contract.Ensure(v != "", "version: empty")
	return v
}

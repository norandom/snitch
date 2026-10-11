package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/norandom/snitch/internal/contract"
)

// version is the build: set at link time by -ldflags "-X main.version=vX.Y.Z" (the release
// workflow), "dev" for a plain go build or go run. Printed by -version and in the startup line.
var version = "dev"

// errVersion: -version was given. It wraps flag.ErrHelp because it is answered the same way:
// printed on the command line, main exits 0, the configuration check is never reached.
var errVersion = fmt.Errorf("-version: %w", flag.ErrHelp)

// stdout is where the command line's answers go (os.Stdout; tests swap it).
var stdout io.Writer = os.Stdout

// printVersion is the -version answer: the version and a newline.
func printVersion(w io.Writer, v string) { fmt.Fprintln(w, mustVersion(v)) }

// startupLine is the journal line after the hooks are attached: which build runs in which mode.
func startupLine(v, mode string, src modeSource) string {
	return fmt.Sprintf("snitchd %s: mode %s (%s), hooks lsm/socket_connect + lsm/socket_sendmsg, maps pinned in %s",
		mustVersion(v), mode, src, pinDir)
}

// mustVersion is the one place the version is read for output: a link with an empty value
// (-X main.version=) would otherwise print an empty line.
func mustVersion(v string) string {
	contract.Ensure(v != "", "version: empty")
	return v
}

// fakedaemon: the stand-in daemon of internal/client/clienttest as a development tool. It
// serves the daemon's API on -api PATH with facts held in memory, reads commands from stdin
// (one per line, see clienttest.StandIn.Do), reports a bad command on stderr and goes on, and
// prints every accepted rule edit as one JSON line on stdout. `quit` or the end of stdin stops it.
//
// Fail-safe implications: none on the host. It loads no kernel program, needs no root, writes
// no rule file and is never released or installed; the operator is the invoking user. It
// refuses to start over a path that exists and is not a socket.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client/clienttest"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// run is the whole tool: flags, the stand-in, then the command loop until quit or EOF.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fakedaemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("api", "", "socket path to serve the API on (required)")
	if err := fs.Parse(args); err != nil || *path == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: fakedaemon -api PATH (commands on stdin)")
		return 2
	}
	var mu sync.Mutex // the edits arrive on connection goroutines
	s, err := clienttest.New(*path, clienttest.Options{
		Operator: uint32(os.Getuid()),
		Record: func(r api.Request) {
			b, _ := json.Marshal(r) // a Request always marshals
			mu.Lock()
			_, _ = fmt.Fprintln(stdout, string(b))
			mu.Unlock()
		},
		Log: func(l string) { _, _ = fmt.Fprintln(stderr, l) },
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fakedaemon:", err)
		return 1
	}
	defer s.Stop()
	_, _ = fmt.Fprintln(stderr, "fakedaemon: serving on "+*path+"; commands on stdin, quit to stop")
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		err := s.Do(sc.Text())
		if errors.Is(err, clienttest.ErrQuit) {
			return 0
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "fakedaemon: %q: %v\n", sc.Text(), err)
		}
	}
	return 0
}

// Command linux-temp-admin is the v2 (Go) rewrite of the temp-admin tool: it
// creates and revokes one-time temporary admin SSH accounts.
package main

import (
	"fmt"
	"os"

	"github.com/xxvcc/linux-temp-admin/internal/cli"
	"golang.org/x/sys/unix"
)

func main() {
	if err := disableCoreDumps(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot disable core dumps:", err)
		os.Exit(1)
	}
	// os.Args is built as make([]string, argc), so an exec with argc == 0 leaves it
	// zero-length and os.Args[1:] panics with a goroutine dump instead of reaching
	// the usage text. cmd/lta-release guards the same way before it indexes.
	args := os.Args
	if len(args) > 0 {
		args = args[1:]
	}
	os.Exit(cli.Run(args))
}

func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	// A pipe-based kernel core_pattern ignores RLIMIT_CORE. Disable dumpability
	// as well before invitation credentials can enter this process's memory.
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

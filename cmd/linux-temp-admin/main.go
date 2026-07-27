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
	os.Exit(cli.Run(os.Args[1:]))
}

func disableCoreDumps() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}

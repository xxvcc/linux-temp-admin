// Command linux-temp-admin is the v2 (Go) rewrite of the temp-admin tool:
// it creates and revokes one-time temporary admin SSH accounts.
//
// This is the P0 scaffold entry point; subcommand dispatch (internal/cli) is
// wired in during P4. For now it exposes version/help so the module builds and
// runs end to end.
package main

import (
	"fmt"
	"os"

	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version", "--version":
		fmt.Println(buildinfo.Version)
		return 0
	case "", "help", "-h", "--help":
		fmt.Printf("%s v%s\n\n", buildinfo.Name, buildinfo.Version)
		fmt.Println("This is the v2 (Go) rewrite in progress. Subcommands are being ported.")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		return 1
	}
}

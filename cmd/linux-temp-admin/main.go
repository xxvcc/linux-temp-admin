// Command linux-temp-admin is the v2 (Go) rewrite of the temp-admin tool: it
// creates and revokes one-time temporary admin SSH accounts.
package main

import (
	"os"

	"github.com/xxvcc/linux-temp-admin/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}

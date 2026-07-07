// Command lta-release is a maintainer-only tool (not shipped) for the release
// pipeline: it generates the ed25519 signing keypair and signs release artifacts
// natively, so releasing needs no openssl.
//
// Usage:
//
//	lta-release keygen <privkey-out>     generate a keypair; write the private
//	                                     key (hex, 0600) and print the PUBLIC key
//	                                     hex to paste into release_pubkey.hex
//	lta-release sign <privkey> <file>    write <file>.sig (raw 64-byte ed25519
//	                                     signature over <file>)
//	lta-release pubkey <privkey>         print the public key hex for a private key
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		mustArgs(3)
		keygen(os.Args[2])
	case "sign":
		mustArgs(4)
		sign(os.Args[2], os.Args[3])
	case "pubkey":
		mustArgs(3)
		fmt.Println(hex.EncodeToString(loadPriv(os.Args[2]).Public().(ed25519.PublicKey)))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lta-release keygen <privkey-out> | sign <privkey> <file> | pubkey <privkey>")
	os.Exit(2)
}

func mustArgs(n int) {
	if len(os.Args) < n {
		usage()
	}
}

func keygen(privOut string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	if dir := filepath.Dir(privOut); dir != "." {
		check(os.MkdirAll(dir, 0o700))
	}
	check(os.WriteFile(privOut, []byte(hex.EncodeToString(priv)+"\n"), 0o600))
	fmt.Fprintf(os.Stderr, "private key written to %s (keep offline)\n", privOut)
	fmt.Fprintln(os.Stderr, "paste this public key into internal/selfmanage/release_pubkey.hex:")
	fmt.Println(hex.EncodeToString(pub))
}

func sign(privFile, file string) {
	priv := loadPriv(privFile)
	data, err := os.ReadFile(file)
	check(err)
	check(os.WriteFile(file+".sig", ed25519.Sign(priv, data), 0o644))
	fmt.Fprintf(os.Stderr, "wrote %s.sig\n", file)
}

func loadPriv(file string) ed25519.PrivateKey {
	b, err := os.ReadFile(file)
	check(err)
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	check(err)
	if len(raw) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "invalid private key length")
		os.Exit(1)
	}
	return ed25519.PrivateKey(raw)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

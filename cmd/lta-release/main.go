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
//	lta-release verify <pubhex> <file> <sig>
//	                                     verify <sig> over <file> against the
//	                                     ed25519 public key in <pubhex> (a hex
//	                                     file like release_pubkey.hex; # and
//	                                     blank lines are skipped). Exit 0 if
//	                                     valid, 1 if not.
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
	case "verify":
		mustArgs(5)
		verify(os.Args[2], os.Args[3], os.Args[4])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lta-release keygen <privkey-out> | sign <privkey> <file> | pubkey <privkey> | verify <pubhex> <file> <sig>")
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

// verify checks a raw ed25519 signature over file against the public key in
// pubHexFile (release_pubkey.hex format: hex on one line, # comments allowed).
// It fails closed: any read/decode/length error or bad signature exits non-zero.
func verify(pubHexFile, file, sigFile string) {
	pub := loadPubHex(pubHexFile)
	data, err := os.ReadFile(file)
	check(err)
	sig, err := os.ReadFile(sigFile)
	check(err)
	// tolerate a single trailing newline on the .sig file
	if n := len(sig); n == ed25519.SignatureSize+1 && sig[n-1] == '\n' {
		sig = sig[:ed25519.SignatureSize]
	}
	if len(sig) != ed25519.SignatureSize {
		fmt.Fprintf(os.Stderr, "invalid signature length: %d (want %d)\n", len(sig), ed25519.SignatureSize)
		os.Exit(1)
	}
	if !ed25519.Verify(pub, data, sig) {
		fmt.Fprintf(os.Stderr, "SIGNATURE INVALID: %s\n", file)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ok: %s verifies against %s\n", file, pubHexFile)
}

// loadPubHex reads an ed25519 public key from a hex file, skipping blank lines
// and lines beginning with '#'. It takes the first remaining hex line.
func loadPubHex(file string) ed25519.PublicKey {
	b, err := os.ReadFile(file)
	check(err)
	var line string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		line = ln
		break
	}
	raw, err := hex.DecodeString(line)
	check(err)
	if len(raw) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "invalid public key length")
		os.Exit(1)
	}
	return ed25519.PublicKey(raw)
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

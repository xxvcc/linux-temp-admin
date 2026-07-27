package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDisableCoreDumps(t *testing.T) {
	if os.Getenv("LTA_CORE_LIMIT_HELPER") == "1" {
		if err := disableCoreDumps(); err != nil {
			t.Fatal(err)
		}
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
			t.Fatal(err)
		}
		if limit.Cur != 0 || limit.Max != 0 {
			t.Fatalf("RLIMIT_CORE=%+v, want both limits zero", limit)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDisableCoreDumps$")
	cmd.Env = append(os.Environ(), "LTA_CORE_LIMIT_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("core-limit helper: %v\n%s", err, out)
	}
}

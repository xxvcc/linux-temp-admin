package schedule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestAtrmJobTreatsAlreadyAbsentAsSuccess(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "atq", "exit 0")
	writeCommand(t, dir, "atrm", "echo should-not-run >&2; exit 1")
	t.Setenv("PATH", dir)

	if err := (realSystem{}).AtrmJob("42"); err != nil {
		t.Fatalf("already-absent at job should be success: %v", err)
	}
}

func TestAtrmJobReportsFailureForStillQueuedJob(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "atq", "printf '42\\tFri Jul 24 00:00:00 2026 a root\\n'")
	writeCommand(t, dir, "atrm", "echo removal-failed >&2; exit 1")
	t.Setenv("PATH", dir)

	err := (realSystem{}).AtrmJob("42")
	if err == nil || !strings.Contains(err.Error(), "removal-failed") {
		t.Fatalf("AtrmJob error = %v, want the real removal failure", err)
	}
}

func TestSystemctlMissingUnitErrorIsPreciselyClassified(t *testing.T) {
	dir := t.TempDir()
	const unit = "linux-temp-admin-v2-revoke-xxvcc-a1.timer"
	writeCommand(t, dir, "systemctl", "echo 'Failed to disable unit: Unit file "+unit+" does not exist.' >&2; exit 1")
	t.Setenv("PATH", dir)

	err := (realSystem{}).Systemctl("disable", "--now", unit)
	if !systemctlUnitFileMissing(err, unit) {
		t.Fatalf("systemctlUnitFileMissing(%v) = false, want true", err)
	}
	if systemctlUnitFileMissing(err, "different.timer") {
		t.Fatal("a missing-unit error must only match its exact target")
	}
}

func TestSystemctlOtherFailureIsNotClassifiedAsMissingUnit(t *testing.T) {
	dir := t.TempDir()
	const unit = "linux-temp-admin-v2-revoke-xxvcc-a1.timer"
	writeCommand(t, dir, "systemctl", "echo 'Failed to connect to bus: Permission denied' >&2; exit 1")
	t.Setenv("PATH", dir)

	err := (realSystem{}).Systemctl("disable", "--now", unit)
	if systemctlUnitFileMissing(err, unit) {
		t.Fatalf("permission failure was misclassified as a missing unit: %v", err)
	}
}

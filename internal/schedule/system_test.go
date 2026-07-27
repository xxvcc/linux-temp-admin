package schedule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
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

func TestSystemctlBoundsOutputAndForcesCLocale(t *testing.T) {
	t.Run("locale", func(t *testing.T) {
		dir := t.TempDir()
		writeCommand(t, dir, "systemctl", "[ \"$LC_ALL\" = C ] || { echo wrong-locale >&2; exit 9; }")
		t.Setenv("PATH", dir)
		t.Setenv("LC_ALL", "C.UTF-8")
		if err := (realSystem{}).Systemctl("daemon-reload"); err != nil {
			t.Fatalf("systemctl did not force LC_ALL=C: %v", err)
		}
	})
	t.Run("output", func(t *testing.T) {
		dir := t.TempDir()
		writeCommand(t, dir, "systemctl", "while :; do printf 0123456789abcdef; done")
		t.Setenv("PATH", dir)
		err := (realSystem{}).Systemctl("daemon-reload")
		if !errors.Is(err, executil.ErrOutputLimit) {
			t.Fatalf("systemctl output error=%v, want output limit", err)
		}
	})
}

func TestSystemctlTimerStateClassification(t *testing.T) {
	const unit = "linux-temp-admin-v2-revoke-xxvcc-a1.timer"
	tests := []struct {
		name  string
		query string
		body  string
		want  bool
	}{
		{name: "disabled", query: "is-enabled", body: "exit 1", want: true},
		{name: "inactive", query: "is-active", body: "exit 3", want: true},
		{name: "unknown", query: "is-active", body: "exit 4", want: true},
		{name: "query failure", query: "is-enabled", body: "echo 'Failed to connect to bus' >&2; exit 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeCommand(t, dir, "systemctl", tt.body)
			t.Setenv("PATH", dir)
			err := (realSystem{}).Systemctl(tt.query, "--quiet", unit)
			if got := systemctlTimerStateNegative(err, tt.query, unit); got != tt.want {
				t.Fatalf("systemctlTimerStateNegative(%v) = %v, want %v", err, got, tt.want)
			}
		})
	}
}

func TestAtJobsFailsClosedWhenInventoryCommandsAreMissing(t *testing.T) {
	t.Run("atq", func(t *testing.T) {
		dir := t.TempDir()
		writeCommand(t, dir, "at", "exit 0")
		t.Setenv("PATH", dir)

		if _, err := (realSystem{}).AtJobs(); err == nil || !strings.Contains(err.Error(), "atq is unavailable") {
			t.Fatalf("AtJobs error = %v, want missing atq", err)
		}
	})

	t.Run("at", func(t *testing.T) {
		dir := t.TempDir()
		writeCommand(t, dir, "atq", "exit 0")
		t.Setenv("PATH", dir)

		if _, err := (realSystem{}).AtJobs(); err == nil || !strings.Contains(err.Error(), "at is unavailable") {
			t.Fatalf("AtJobs error = %v, want missing at", err)
		}
	})
}

func TestAtJobsInventoryDoesNotRequireAtrm(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "atq", "printf '42\\tFri Jul 24 00:00:00 2026 a root\\n'")
	writeCommand(t, dir, "at", "printf '%s\\n' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes'")
	t.Setenv("PATH", dir)

	jobs, err := (realSystem{}).AtJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].ID != "42" || !strings.Contains(jobs[0].Body, "revoke --user xxvcc-a1") {
		t.Fatalf("AtJobs = %#v, want job 42 without atrm installed", jobs)
	}
}

func TestAtJobsSkipsJobThatDisappearsAfterAtq(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "listed")
	writeCommand(t, dir, "atq", "if [ -f '"+marker+"' ]; then exit 0; fi\n: > '"+marker+"'\nprintf '42\\tFri Jul 24 00:00:00 2026 a root\\n'")
	writeCommand(t, dir, "at", "exit 1")
	t.Setenv("PATH", dir)

	jobs, err := (realSystem{}).AtJobs()
	if err != nil {
		t.Fatalf("a job firing between atq and at -c should be ignored: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("AtJobs = %#v, want vanished job omitted", jobs)
	}
}

func TestAtJobsBoundsWholeInventorySizeAndTime(t *testing.T) {
	t.Run("aggregate body size", func(t *testing.T) {
		dir := t.TempDir()
		writeCommand(t, dir, "atq", "printf '1 x\\n2 x\\n'")
		writeCommand(t, dir, "at", "printf '12345\\n'")
		t.Setenv("PATH", dir)
		oldLimit := atInventoryMaxBodyBytes
		atInventoryMaxBodyBytes = 8
		t.Cleanup(func() { atInventoryMaxBodyBytes = oldLimit })

		if _, err := (realSystem{}).AtJobs(); err == nil || !strings.Contains(err.Error(), "inventory exceeds 8 bytes") {
			t.Fatalf("AtJobs aggregate-limit error = %v", err)
		}
	})

	t.Run("whole inventory timeout", func(t *testing.T) {
		dir := t.TempDir()
		writeCommand(t, dir, "atq", "printf '1 x\\n'")
		writeCommand(t, dir, "at", "/bin/sleep 30")
		t.Setenv("PATH", dir)
		oldTimeout := atInventoryTimeout
		atInventoryTimeout = 50 * time.Millisecond
		t.Cleanup(func() { atInventoryTimeout = oldTimeout })

		start := time.Now()
		_, err := (realSystem{}).AtJobs()
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
			t.Fatalf("AtJobs timeout error=%v elapsed=%s", err, time.Since(start))
		}
	})
}

func TestEnsureAtdRejectsWhenNoProbeCanConfirmIt(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "at", "exit 0")
	t.Setenv("PATH", dir)

	if ensureAtd() {
		t.Fatal("ensureAtd reported success without any way to confirm atd is running")
	}
}

func TestEnsureAtdDoesNotTrustServiceStartExitAlone(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "start-called")
	writeCommand(t, dir, "service", "if [ \"$2\" = start ]; then : > '"+marker+"'; exit 0; fi; exit 1")
	t.Setenv("PATH", dir)

	if ensureAtd() {
		t.Fatal("ensureAtd trusted service start without a successful status or process probe")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("service start was not attempted: %v", err)
	}
}

func TestScheduleAtRequiresCancellationToolsBeforeQueueing(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "queued")
	writeCommand(t, dir, "at", "touch '"+marker+"'")
	writeCommand(t, dir, "atq", "exit 0")
	t.Setenv("PATH", dir)

	_, err := (realSystem{}).ScheduleAt("true", 1)
	if err == nil || !strings.Contains(err.Error(), "atrm is unavailable") {
		t.Fatalf("ScheduleAt error = %v, want missing atrm refusal", err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("at was invoked before cancellation tooling was proved available")
	}
}

func TestScheduleAtForcesCLocaleBeforeParsingJobID(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "atq", "exit 0")
	writeCommand(t, dir, "atrm", "exit 0")
	writeCommand(t, dir, "pgrep", "exit 0")
	writeCommand(t, dir, "at", "[ \"$LC_ALL\" = C ] || { echo localized-output >&2; exit 9; }; while read line; do :; done; echo 'job 7 at Fri Jul 24 00:00:00 2026'")
	t.Setenv("PATH", dir)
	t.Setenv("LC_ALL", "C.UTF-8")

	id, err := (realSystem{}).ScheduleAt("true", 1)
	if err != nil || id != "7" {
		t.Fatalf("ScheduleAt id=%q err=%v, want C-locale job 7", id, err)
	}
}

func TestRemoveAtJobsForMatchesOnlyKnownStandaloneRevokeCommand(t *testing.T) {
	dir := t.TempDir()
	removed := filepath.Join(dir, "removed")
	writeCommand(t, dir, "atq", "printf '1 x\\n2 x\\n3 x\\n4 x\\n5 x\\n'")
	writeCommand(t, dir, "at", `case "$2" in
1) printf '%s\n' '# /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes' ;;
2) printf '%s\n' 'echo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes' ;;
3) printf '%s\n' '/usr/local/sbin/linux-temp-admin-helper revoke --user xxvcc-a1 --yes' ;;
4) printf '%s\n' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --unknown' ;;
5) printf '%s\n' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef' ;;
esac`)
	writeCommand(t, dir, "atrm", "printf '%s\\n' \"$1\" >> '"+removed+"'")
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	if err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(removed)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != "5" {
		t.Fatalf("removed jobs = %q, want only the owned job 5", got)
	}
}

func TestParseAtRevokeCommandRejectsReservedLinuxUID(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot represent the reserved uint32 uid sentinel")
	}
	command := "/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 4294967295 --generation 0123456789abcdef0123456789abcdef"
	if parsed, ok := parseAtRevokeCommand(command, "/usr/local/sbin/linux-temp-admin"); ok {
		t.Fatalf("parseAtRevokeCommand accepted the reserved Linux UID: %#v", parsed)
	}
}

func TestRemoveAtJobsForAllowsCompletelyAbsentAtBackend(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	if err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1")); err != nil {
		t.Fatalf("systemd-only cleanup failed because optional at is absent: %v", err)
	}
}

func TestRemoveAtJobsForFailsClosedOnPartialAtBackend(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "atd", "exit 0")
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1"))
	if err == nil || !strings.Contains(err.Error(), "atq is unavailable") {
		t.Fatalf("partial at backend error = %v, want inventory failure", err)
	}
}

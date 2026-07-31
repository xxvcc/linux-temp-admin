package schedule

import (
	"context"
	"errors"
	"fmt"
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

func TestRealSystemHasAtDetectsEveryBackendFootprint(t *testing.T) {
	for _, command := range []string{"at", "atq", "atrm", "atd", "batch"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			writeCommand(t, dir, command, "exit 0")
			t.Setenv("PATH", dir)
			if !(realSystem{}).HasAt() {
				t.Fatalf("HasAt did not detect %s", command)
			}
		})
	}
	t.Run("absent", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if (realSystem{}).HasAt() {
			t.Fatal("HasAt reported an absent backend")
		}
	})
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

func TestSystemctlStoppedStateRejectsActivating(t *testing.T) {
	const unit = "linux-temp-admin-v2-revoke-xxvcc-a1.timer"
	for _, tc := range []struct {
		state string
		exit  int
		want  bool
	}{
		{state: "inactive", exit: 3, want: true},
		{state: "failed", exit: 3, want: true},
		{state: "unknown", exit: 4, want: true},
		{state: "activating", exit: 3, want: false},
		{state: "deactivating", exit: 3, want: false},
	} {
		t.Run(tc.state, func(t *testing.T) {
			dir := t.TempDir()
			writeCommand(t, dir, "systemctl", fmt.Sprintf("echo %s; exit %d", tc.state, tc.exit))
			t.Setenv("PATH", dir)
			err := (realSystem{}).Systemctl("is-active", unit)
			if got := systemctlTimerStoppedState(err, unit); got != tc.want {
				t.Fatalf("systemctlTimerStoppedState(%v) = %v, want %v", err, got, tc.want)
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
	writeCommand(t, dir, "at", "printf '%s\\n' '# atrun uid=0 gid=0' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes'")
	t.Setenv("PATH", dir)

	jobs, err := (realSystem{}).AtJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].ID != "42" || jobs[0].OwnerUID != 0 || !strings.Contains(jobs[0].Body, "revoke --user xxvcc-a1") {
		t.Fatalf("AtJobs = %#v, want job 42 without atrm installed", jobs)
	}
}

func TestAtJobsRequiresCanonicalOwnerHeader(t *testing.T) {
	for _, body := range []string{
		"/usr/local/sbin/linux-temp-admin revoke --user forged --yes\n",
		"# atrun owner unknown\n# atrun uid=0 gid=0\n",
		"# atrun uid=4294967295 gid=0\n",
	} {
		dir := t.TempDir()
		writeCommand(t, dir, "atq", "printf '42 x\\n'")
		writeCommand(t, dir, "at", "printf '%s' '"+body+"'")
		t.Setenv("PATH", dir)
		if _, err := (realSystem{}).AtJobs(); err == nil {
			t.Fatalf("AtJobs accepted owner body %q: %v", body, err)
		}
	}
}

func TestAtJobsSkipsOversizedNonRootBodyAfterOwnerProbe(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "atq", "printf '42 x\\n'")
	writeCommand(t, dir, "at", "printf '%s\\n' '# atrun uid=1001 gid=1001'; while :; do printf 0123456789abcdef; done")
	t.Setenv("PATH", dir)

	jobs, err := (realSystem{}).AtJobs()
	if err != nil {
		t.Fatalf("oversized non-root body poisoned root inventory: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != "42" || jobs[0].OwnerUID != 1001 || jobs[0].Body != "" {
		t.Fatalf("AtJobs = %#v, want owner-only non-root inventory", jobs)
	}
}

func TestAtQueueParsingFailsClosedOnMalformedOrDuplicateLines(t *testing.T) {
	for _, output := range []string{
		"warning: partial queue output\n42 x\n",
		"42 x\n42 duplicate\n",
	} {
		if _, err := parseAtQueueIDs(output); err == nil {
			t.Fatalf("parseAtQueueIDs(%q) succeeded, want incomplete-inventory refusal", output)
		}
	}

	dir := t.TempDir()
	writeCommand(t, dir, "atq", "printf '%s\\n' 'corrupt queue line'")
	t.Setenv("PATH", dir)
	if queued, err := atJobQueued("42"); err == nil || queued {
		t.Fatalf("atJobQueued malformed inventory = %v, %v; want false, error", queued, err)
	}
}

func TestAtJobsRejectsMalformedQueueInsteadOfSilentlySkippingIt(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "at-called")
	writeCommand(t, dir, "atq", "printf 'broken-line\\n42 x\\n'")
	writeCommand(t, dir, "at", ": > '"+marker+"'")
	t.Setenv("PATH", dir)

	if _, err := (realSystem{}).AtJobs(); err == nil || !strings.Contains(err.Error(), "parse atq line 1") {
		t.Fatalf("AtJobs malformed queue error = %v", err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("AtJobs inspected bodies after malformed queue: %v", err)
	}
}

func TestLoadedSystemdUnitsParsesBoundedCompleteInventory(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "systemctl", `printf '%s\n' \
  'linux-temp-admin-v2-revoke-loaded.timer loaded active waiting description' \
  'linux-temp-admin-v2-revoke-loaded.service loaded inactive dead'`)
	t.Setenv("PATH", dir)

	units, err := (realSystem{}).loadedSystemdUnits()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(units, ",") != "linux-temp-admin-v2-revoke-loaded.timer,linux-temp-admin-v2-revoke-loaded.service" {
		t.Fatalf("loaded systemd units = %v", units)
	}
	if _, err := parseLoadedSystemdUnits("truncated output\n"); err == nil {
		t.Fatal("parseLoadedSystemdUnits accepted an incomplete manager line")
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
		writeCommand(t, dir, "at", "printf '%s\\n' '# atrun uid=0 gid=0' '12345'")
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

func TestEnsureAtdPgrepFallbackRequiresRootRealUID(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "pgrep", `[ "$1" = -x ] && [ "$2" = -U ] && [ "$3" = 0 ] && [ "$4" = atd ]`)
	t.Setenv("PATH", dir)

	if !ensureAtd() {
		t.Fatal("ensureAtd did not accept the root-bound pgrep confirmation")
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

	_, err := (realSystem{}).ScheduleAt("true", time.Date(2030, 1, 2, 3, 4, 0, 0, time.UTC))
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
	writeCommand(t, dir, "at", "[ \"$LC_ALL\" = C ] || { echo localized-output >&2; exit 9; }; [ \"$TZ\" = UTC ] || { echo wrong-timezone >&2; exit 8; }; [ \"$1\" = -t ] && [ \"$2\" = 203001020804 ] || { echo wrong-deadline >&2; exit 7; }; IFS= read -r first; IFS= read -r second; [ \"$first\" = 'unset TZ' ] && [ \"$second\" = true ] || { echo wrong-job-body >&2; exit 6; }; echo 'job 7 at Fri Jul 24 00:00:00 2026'")
	t.Setenv("PATH", dir)
	t.Setenv("LC_ALL", "C.UTF-8")

	id, err := (realSystem{}).ScheduleAt("true", time.Date(2030, 1, 2, 3, 4, 0, 0, time.FixedZone("local", -5*60*60)))
	if err != nil || id != "7" {
		t.Fatalf("ScheduleAt id=%q err=%v, want C-locale job 7", id, err)
	}
}

func TestScheduleAtRollsBackAmbiguouslySubmittedJob(t *testing.T) {
	for _, tc := range []struct {
		name      string
		queueExit string
		want      string
	}{
		{name: "command error after queue", queueExit: "echo queued-but-failed >&2; exit 1", want: "queued-but-failed"},
		{name: "unparseable job id", queueExit: "echo accepted-without-an-id; exit 0", want: "could not parse at job id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			queued := filepath.Join(dir, "queued")
			body := filepath.Join(dir, "body")
			removed := filepath.Join(dir, "removed")
			writeCommand(t, dir, "pgrep", "exit 0")
			writeCommand(t, dir, "atq", "[ -f '"+queued+"' ] && printf '42 x\\n'; exit 0")
			writeCommand(t, dir, "atrm", "/bin/rm -f '"+queued+"'; printf '%s\\n' \"$1\" > '"+removed+"'")
			writeCommand(t, dir, "at", `if [ "$1" = "-c" ]; then
			  printf '%s\n' '# atrun uid=0 gid=0'
			  /bin/cat '`+body+`'
  exit 0
fi
/bin/cat > '`+body+`'
: > '`+queued+`'
`+tc.queueExit)
			t.Setenv("PATH", dir)

			command := "/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef"
			_, scheduleErr := (realSystem{}).ScheduleAt(command, time.Date(2030, 1, 2, 3, 4, 0, 0, time.UTC))
			if scheduleErr == nil || !strings.Contains(scheduleErr.Error(), tc.want) {
				t.Fatalf("ScheduleAt error = %v, want %q", scheduleErr, tc.want)
			}
			if _, err := os.Lstat(queued); !os.IsNotExist(err) {
				t.Fatalf("ambiguously submitted job survived rollback: stat=%v schedule=%v", err, scheduleErr)
			}
			if got, err := os.ReadFile(removed); err != nil || strings.TrimSpace(string(got)) != "42" {
				t.Fatalf("rolled-back job id = %q err=%v, want 42", got, err)
			}
		})
	}
}

func TestRemoveAtJobsForMatchesOnlyKnownStandaloneRevokeCommand(t *testing.T) {
	dir := t.TempDir()
	removed := filepath.Join(dir, "removed")
	writeCommand(t, dir, "atq", "printf '1 x\\n2 x\\n3 x\\n'; [ -f '"+removed+"' ] || printf '5 x\\n'")
	writeCommand(t, dir, "at", `printf '%s\n' '# atrun uid=0 gid=0'
	case "$2" in
	1) printf '%s\n' '# /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes' ;;
	2) printf '%s\n' 'echo /usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes' ;;
	3) printf '%s\n' '/usr/local/sbin/linux-temp-admin-helper revoke --user xxvcc-a1 --yes' ;;
5) [ ! -f '`+removed+`' ] || exit 1
   printf '%s\n' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef' ;;
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

func TestRemoveAtJobsForIgnoresNonRootMimic(t *testing.T) {
	dir := t.TempDir()
	removed := filepath.Join(dir, "removed")
	writeCommand(t, dir, "atq", "printf '9 x\\n'")
	writeCommand(t, dir, "at", "printf '%s\\n' '# atrun uid=1001 gid=1001' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --unknown'")
	writeCommand(t, dir, "atrm", "printf '%s\\n' \"$1\" > '"+removed+"'")
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	if err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1")); err != nil {
		t.Fatalf("non-root mimic poisoned root schedule cleanup: %v", err)
	}
	if _, err := os.Lstat(removed); !os.IsNotExist(err) {
		t.Fatalf("non-root mimic reached atrm: %v", err)
	}
}

func TestRemoveAtJobsForDoesNotDeleteAReusedJobID(t *testing.T) {
	dir := t.TempDir()
	reads := filepath.Join(dir, "reads")
	removed := filepath.Join(dir, "removed")
	writeCommand(t, dir, "atq", "printf '7 x\\n'")
	writeCommand(t, dir, "at", `count=0
if [ -f '`+reads+`' ]; then count=$(/bin/cat '`+reads+`'); fi
count=$((count + 1))
	printf '%s\n' "$count" > '`+reads+`'
	printf '%s\n' '# atrun uid=0 gid=0'
	if [ "$count" -eq 1 ]; then
  printf '%s\n' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef'
else
  printf '%s\n' '/usr/bin/true'
fi`)
	writeCommand(t, dir, "atrm", "printf '%s\\n' \"$1\" > '"+removed+"'")
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	if err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(removed); !os.IsNotExist(err) {
		t.Fatalf("replacement job reached atrm through a reused ID: %v", err)
	}
}

func TestRemoveAtJobsForVerifiesAtrmSuccess(t *testing.T) {
	dir := t.TempDir()
	writeCommand(t, dir, "atq", "printf '7 x\\n'")
	writeCommand(t, dir, "at", "printf '%s\\n' '# atrun uid=0 gid=0' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef'")
	writeCommand(t, dir, "atrm", "exit 0")
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1"))
	if err == nil || !strings.Contains(err.Error(), "reported success but the matching job remains") {
		t.Fatalf("RemoveAtJobsFor no-op atrm error = %v, want surviving-target refusal", err)
	}
}

func TestRemoveAtJobsForAcceptsReusedIDAfterAtrmSuccess(t *testing.T) {
	dir := t.TempDir()
	reads := filepath.Join(dir, "reads")
	writeCommand(t, dir, "atq", "printf '7 x\\n'")
	writeCommand(t, dir, "at", `count=0
if [ -f '`+reads+`' ]; then count=$(/bin/cat '`+reads+`'); fi
count=$((count + 1))
	printf '%s\n' "$count" > '`+reads+`'
	printf '%s\n' '# atrun uid=0 gid=0'
	if [ "$count" -le 2 ]; then
  printf '%s\n' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --force --confirm-force xxvcc-a1 --expected-uid 1001 --generation 0123456789abcdef0123456789abcdef'
else
  printf '%s\n' '/usr/bin/true'
fi`)
	writeCommand(t, dir, "atrm", "exit 0")
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	if err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1")); err != nil {
		t.Fatalf("post-atrm ID reuse was treated as a surviving target: %v", err)
	}
}

func TestRemoveAtJobsForFailsClosedOnMalformedOwnedCommand(t *testing.T) {
	dir := t.TempDir()
	removed := filepath.Join(dir, "removed")
	writeCommand(t, dir, "atq", "printf '4 x\\n'")
	writeCommand(t, dir, "at", "printf '%s\\n' '# atrun uid=0 gid=0' '/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes --unknown'")
	writeCommand(t, dir, "atrm", "printf '%s\\n' \"$1\" > '"+removed+"'")
	t.Setenv("PATH", dir)

	s := newScheduler(dir, realSystem{})
	err := (realSystem{}).RemoveAtJobsFor(s.revokeAtNeedle("xxvcc-a1"))
	if err == nil || !strings.Contains(err.Error(), "unsupported or corrupt") {
		t.Fatalf("RemoveAtJobsFor error = %v, want malformed owned-job refusal", err)
	}
	if _, err := os.Lstat(removed); !os.IsNotExist(err) {
		t.Fatalf("malformed job was removed instead of preserved: %v", err)
	}
}

func TestRemoveAtJobsForDetectsMalformedTargetWithReorderedOrEqualsUserFlag(t *testing.T) {
	for _, command := range []string{
		"/usr/local/sbin/linux-temp-admin revoke --yes --user xxvcc-a1 --unknown",
		"/usr/local/sbin/linux-temp-admin revoke --user=xxvcc-a1 --yes --unknown",
		"/usr/local/sbin/linux-temp-admin revoke -user xxvcc-a1 --yes --unknown",
	} {
		t.Run(command, func(t *testing.T) {
			match, err := atBodyHasKnownRevoke(command, "/usr/local/sbin/linux-temp-admin", "xxvcc-a1")
			if err == nil || match {
				t.Fatalf("atBodyHasKnownRevoke(%q) = %v, %v; want false, error", command, match, err)
			}
		})
	}
}

func TestAtBodyKnownRevokeScansPastMatchForMalformedOwnedCommand(t *testing.T) {
	body := "/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes\n" +
		"/usr/local/sbin/linux-temp-admin revoke --yes --user xxvcc-a1 --unknown\n"
	match, err := atBodyHasKnownRevoke(body, "/usr/local/sbin/linux-temp-admin", "xxvcc-a1")
	if err == nil || match {
		t.Fatalf("atBodyHasKnownRevoke mixed body = %v, %v; want false, error", match, err)
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

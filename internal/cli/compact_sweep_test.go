package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/sshdconf"
	"github.com/xxvcc/linux-temp-admin/internal/sudoers"
)

// compactOrphanHost seeds a host that has exactly one orphaned auto-revoke task:
// a unit pair on disk for a username with no registry row and no account. That is
// what makes Scheduler.Orphans return a name and the sweep loop — the only place
// the keep-the-task guard lives — actually execute.
func compactOrphanHost(t *testing.T, user string) (*App, *strings.Builder, *recordingCanceller) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("the registry state directory must be root-owned")
	}
	a, _, _ := newTestApp(t, "")
	var errb strings.Builder
	a.Err = &errb
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}

	systemdDir := t.TempDir()
	sys := &recordingCanceller{}
	a.Scheduler = &schedule.Scheduler{
		SystemdDir:  systemdDir,
		InstallPath: a.InstallPath,
		UnitPrefix:  "linux-temp-admin-v2-revoke-",
		Now:         a.Now,
		Sys:         sys,
	}
	for _, suffix := range []string{".service", ".timer"} {
		path := filepath.Join(systemdDir, "linux-temp-admin-v2-revoke-"+user+suffix)
		if err := os.WriteFile(path, []byte("# orphan\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Prove the premise: without it the sweep loop never runs and any assertion
	// below would be vacuous.
	orphans, err := a.Scheduler.Orphans(a.accountIsOursAndLive)
	if err != nil {
		t.Fatalf("seeding an orphan task: %v", err)
	}
	if len(orphans) != 1 || orphans[0] != user {
		t.Fatalf("orphan sweep sees %v, want exactly [%s]; the guarded loop would not execute", orphans, user)
	}
	return a, &errb, sys
}

// Cancelling an orphan's auto-revoke task is what makes a leftover NOPASSWD
// drop-in permanent: the task is the only remaining thing that would have removed
// it. So a run that could not enumerate or could not remove the grants must leave
// the task armed.
func TestCompactKeepsTheAutoRevokeTaskWhenGrantCleanupIsUnconfirmed(t *testing.T) {
	const user = "xxvcc-orphan1"

	t.Run("the grant sweep could not enumerate", func(t *testing.T) {
		a, errb, sys := compactOrphanHost(t, user)
		// An unreadable sudoers directory: enumeration cannot answer at all.
		a.Sudoers = &sudoers.Manager{Dir: a.Registry.File}

		rc := a.compactLocked()

		if len(sys.cancelled) != 0 {
			t.Fatalf("cancelled %v while the grant sweep could not enumerate", sys.cancelled)
		}
		if got := errb.String(); !strings.Contains(got, "keeping the auto-delete task") || !strings.Contains(got, user) {
			t.Fatalf("stderr = %q, want the keep-the-task line naming %s", got, user)
		}
		if rc == 0 {
			t.Fatal("compact reported success though it could not confirm the grants were removed")
		}
	})

	t.Run("a confirmed-clean sweep still cancels the orphan task", func(t *testing.T) {
		a, errb, sys := compactOrphanHost(t, user)
		// A readable, empty sudoers dir: enumeration succeeds and finds nothing.
		a.Sudoers = &sudoers.Manager{Dir: t.TempDir()}

		a.compactLocked()

		if len(sys.cancelled) == 0 {
			t.Fatalf("the orphan task was kept even though the grant sweep was clean; stderr=%q", errb.String())
		}
		if got := errb.String(); strings.Contains(got, "keeping the auto-delete task") {
			t.Fatalf("stderr = %q, want no keep-the-task line on a clean sweep", got)
		}
	})
}

// recordingCanceller reports a systemd host and records the units Cancel touches,
// so the test can tell "the task was cancelled" from "the task was kept".
type recordingCanceller struct {
	revokeTestScheduleSystem
	cancelled []string
}

func (r *recordingCanceller) HasSystemctl() bool { return true }

func (r *recordingCanceller) Systemctl(args ...string) error {
	for _, a := range args {
		if strings.HasPrefix(a, "linux-temp-admin-") {
			r.cancelled = append(r.cancelled, a)
		}
	}
	return nil
}

func (r *recordingCanceller) ScheduleAt(string, time.Time) (string, error) {
	return "", nil
}

// A missing drop-in is not proof that a running daemon forgot its exception.
// Keep the retry until Remove confirms both validation and reload succeeded.
func TestCompactDistinguishesARemovedGrantFromASurvivingOne(t *testing.T) {
	const user = "xxvcc-orphan2"

	t.Run("removed but not reloaded keeps the task until retry succeeds", func(t *testing.T) {
		a, errb, sys := compactOrphanHost(t, user)
		dir := t.TempDir()
		reloadCalls := 0
		a.SSHD = &sshdconf.Manager{Dir: dir, Validate: func() error { return nil }, Reload: func() error {
			reloadCalls++
			return sshdconf.ErrNoReloadMechanism
		}}
		a.Sudoers = &sudoers.Manager{Dir: t.TempDir()}
		// The drop-in exists, so the sweep finds it and removes it; only the reload
		// cannot be performed.
		if err := os.WriteFile(a.SSHD.FilePath(user), []byte("Match User "+user+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		a.compactLocked()

		if _, err := os.Lstat(a.SSHD.FilePath(user)); !os.IsNotExist(err) {
			t.Fatalf("the drop-in survived the sweep: %v", err)
		}
		if reloadCalls != 1 {
			t.Fatalf("reload calls = %d, want 1", reloadCalls)
		}
		if _, err := os.Lstat(a.SSHD.FilePath(user) + ".remove-pending"); err != nil {
			t.Fatalf("pending removal evidence missing: %v", err)
		}
		if len(sys.cancelled) != 0 {
			t.Fatalf("cancelled %v before reload confirmation; stderr=%q", sys.cancelled, errb.String())
		}
		a.SSHD.Reload = func() error { reloadCalls++; return nil }
		if rc := a.compactLocked(); rc != 0 {
			t.Fatalf("retry failed: %s", errb.String())
		}
		if reloadCalls != 2 || len(sys.cancelled) == 0 {
			t.Fatalf("successful retry did not reload and cancel: reloads=%d cancelled=%v", reloadCalls, sys.cancelled)
		}
		if _, err := os.Lstat(a.SSHD.FilePath(user) + ".remove-pending"); !os.IsNotExist(err) {
			t.Fatalf("pending removal survived confirmed reload: %v", err)
		}
	})

	t.Run("a drop-in that really survived pins the task", func(t *testing.T) {
		a, errb, sys := compactOrphanHost(t, user)
		a.SSHD = &sshdconf.Manager{Dir: t.TempDir(), Reload: func() error { return nil }}
		a.Sudoers = &sudoers.Manager{Dir: t.TempDir()}
		// A directory at the drop-in path: the sweep sees the managed name, its
		// removal genuinely fails, and the path is still there afterwards. This is
		// the one case that must still pin the task.
		if err := os.Mkdir(a.SSHD.FilePath(user), 0o700); err != nil {
			t.Fatal(err)
		}

		a.compactLocked()

		if _, err := os.Lstat(a.SSHD.FilePath(user)); err != nil {
			t.Fatalf("the artifact vanished, so this case no longer tests a survivor: %v", err)
		}
		if len(sys.cancelled) != 0 {
			t.Fatalf("cancelled %v while the drop-in is still on disk; stderr=%q", sys.cancelled, errb.String())
		}
	})
}

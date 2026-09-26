package cli

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

// An unreadable registry is not an empty one. The picker used to say "no
// registered temporary users" and point at --force — a statement about
// registration the failed read could not support, on the one command whose next
// step is deletion.
func TestRevokePickerRefusesToCallAnUnreadableRegistryEmpty(t *testing.T) {
	a, _, errb := newTestApp(t, "xxvcc-a1\n")
	// A directory where the registry file belongs: readable path, unreadable rows.
	if err := os.Mkdir(a.Registry.File, 0o700); err != nil {
		t.Fatal(err)
	}

	picked, ok := a.selectUser()
	if ok {
		t.Fatalf("selectUser returned %q on an unreadable registry, want a refusal", picked)
	}
	got := errb.String()
	if strings.Contains(got, "no registered temporary users") {
		t.Fatalf("stderr = %q, want no claim that the registry is empty", got)
	}
	if !strings.Contains(got, "the registry could not be read") {
		t.Fatalf("stderr = %q, want the real reason", got)
	}
	if strings.Contains(got, "--force") {
		t.Fatalf("stderr = %q, want no --force suggestion for a possibly-registered account", got)
	}
}

// A genuinely empty registry still prompts: revoke --force exists to dig out an
// account whose row was lost, and the only way to name it is to type it.
func TestRevokePickerStillPromptsOnAGenuinelyEmptyRegistry(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Registry.Init writes root-owned state and requires root")
	}
	a, _, errb := newTestApp(t, "xxvcc-a1\n")
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}

	picked, ok := a.selectUser()
	if !ok || picked != "xxvcc-a1" {
		t.Fatalf("selectUser = %q, %v; want the typed name accepted", picked, ok)
	}
	if !strings.Contains(errb.String(), "no registered temporary users") {
		t.Fatalf("stderr = %q, want the empty-registry notice", errb.String())
	}
}

// The first identity check runs before anything is attempted. Reporting it as
// "could not fully disable the login" told the operator a step had been tried and
// failed, and sent them looking at the wrong thing.
func TestTeardownDistinguishesAnIdentityChangeFromAFailedDisable(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	expected := user.Passwd{Name: "xxvcc-a1", UID: 1500, GID: 1500, Home: "/home/xxvcc-a1"}

	t.Run("the quarantined (async) teardown reports it the same way", func(t *testing.T) {
		// deleteAndFinalize picks teardownQuarantinedAccount whenever a quarantine
		// deadline is recorded and finalization is not synchronous — the ordinary
		// deletion path. The fix touched both teardowns, so both must be pinned.
		a, _, _ := newTestApp(t, "")
		var disableCalls int
		a.LookupUser = func(string) (user.Passwd, bool, error) {
			// A different account now wears the name: identity no longer matches.
			return user.Passwd{Name: "xxvcc-a1", UID: 4242, GID: 4242, Home: "/home/someone-else"}, true, nil
		}
		runner := &recordingRunner{calls: &disableCalls}
		a.Users = &user.Manager{LookupUser: a.LookupUser, Runner: runner}

		stage, err := a.teardownQuarantinedAccount("xxvcc-a1", expected, func() error { return nil }, false)
		if stage != revokeIdentityUnstable {
			t.Fatalf("stage = %v, want revokeIdentityUnstable on the async path too", stage)
		}
		if err == nil {
			t.Fatal("want the identity error returned")
		}
		if disableCalls != 0 {
			t.Fatalf("%d account-mutating commands ran before the identity check passed", disableCalls)
		}
	})

	t.Run("identity changed before any action", func(t *testing.T) {
		stage, err := a.teardownLocalAccountWith("xxvcc-a1", expected, func() error { return nil },
			func(string, user.Passwd) error { return errors.New("passwd entry no longer matches") },
			func(string, user.Passwd, func() error) error {
				t.Fatal("deleteExpected must not run after the identity check failed")
				return nil
			})
		if stage != revokeIdentityUnstable {
			t.Fatalf("stage = %v, want revokeIdentityUnstable", stage)
		}
		if err == nil {
			t.Fatal("want the identity error returned")
		}
	})
}

// The quarantine window has to cover one complete cron/at polling cycle, or the
// name, UID and GID return to the allocatable pool while a cached deferred job
// for that identity can still be dispatched. Replacing the round-up with
// truncation leaves ~5 s of quarantine and used to break nothing.
func TestQuarantineDeadlineNeverFallsBelowTheConfiguredFloor(t *testing.T) {
	floor := time.Duration(config.IdentityQuarantineSeconds) * time.Second
	base := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)

	for second := 0; second < 60; second++ {
		for _, nanos := range []int{0, 1, 999999999} {
			now := base.Add(time.Duration(second)*time.Second + time.Duration(nanos))
			got := quarantineDeadline(now)

			if window := got.Sub(now); window < floor {
				t.Fatalf("quarantineDeadline(%s) gives a %s window, want at least %s", now.Format(time.RFC3339Nano), window, floor)
			}
			// Bounded on the other side too: the window is a floor, not an excuse to
			// hold an identity out of the pool for minutes.
			if window := got.Sub(now); window >= floor+time.Minute {
				t.Fatalf("quarantineDeadline(%s) gives a %s window, want under %s", now.Format(time.RFC3339Nano), window, floor+time.Minute)
			}
			// Minute-aligned in UTC: at(1) and OnCalendar both take whole minutes,
			// and registry validation refuses a deadline carrying seconds.
			if got.Second() != 0 || got.Nanosecond() != 0 || got.Location() != time.UTC {
				t.Fatalf("quarantineDeadline(%s) = %s, want a whole UTC minute", now.Format(time.RFC3339Nano), got.Format(time.RFC3339Nano))
			}
		}
	}
}

// recordingRunner counts every account-mutating command. The pre-teardown
// identity check must run before any of them.
type recordingRunner struct{ calls *int }

func (recordingRunner) Look(string) bool { return true }
func (r recordingRunner) Run(string, ...string) error {
	*r.calls++
	return nil
}
func (r recordingRunner) RunInput(string, string, ...string) error {
	*r.calls++
	return nil
}

// The audit log is what an incident reviewer reads after the fact. It used to
// state "grants stripped" on a protected revoke whose grant removal had failed,
// so the reviewer concluded a NOPASSWD drop-in was gone while it was still
// granting root.
func TestProtectedRevokeAuditDetailMatchesWhatActuallyHappened(t *testing.T) {
	for _, tc := range []struct {
		name       string
		grantErr   error
		wantDetail string
		notDetail  string
	}{
		{"grants really were stripped", nil, "grants stripped", "NOT fully stripped"},
		{"grant removal failed", errors.New("sudoers remove failed"), "grants NOT fully stripped: sudoers remove failed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail := protectedRevokeAuditDetail(tc.grantErr)
			if !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("audit detail = %q, want it to contain %q", detail, tc.wantDetail)
			}
			if tc.notDetail != "" && strings.Contains(detail, tc.notDetail) {
				t.Fatalf("audit detail = %q, want it not to contain %q", detail, tc.notDetail)
			}
		})
	}
}

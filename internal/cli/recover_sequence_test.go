package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/lifecycle"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

func missingSequenceFixture(t *testing.T, a *App, rec *registry.Record) string {
	t.Helper()
	requireRootRegistryFixture(t)
	if rec == nil {
		if err := a.Registry.Init(); err != nil {
			t.Fatal(err)
		}
	} else {
		setTestRegistryRecord(t, a, *rec)
	}
	a.Registry.Now = a.Now
	path := filepath.Join(a.Registry.Dir, "identity-sequence")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("path %s exists or could not be inspected: %v", path, err)
	}
}

func TestIdentitySequenceHighWaterFlagRequiresCanonicalLinuxID(t *testing.T) {
	valid := []string{"0", "1", "1000", "2147483647"}
	if strconv.IntSize >= 64 {
		valid = append(valid, "4294967294")
	}
	for _, value := range valid {
		t.Run("valid "+value, func(t *testing.T) {
			var flag identitySequenceHighWaterFlag
			if err := flag.Set(value); err != nil {
				t.Fatalf("Set(%q): %v", value, err)
			}
			want, err := strconv.Atoi(value)
			if err != nil {
				t.Fatal(err)
			}
			if !flag.set || flag.text != value || flag.value != want || flag.String() != value {
				t.Fatalf("Set(%q) produced %+v", value, flag)
			}
			if err := flag.Set(value); err == nil || !strings.Contains(err.Error(), "only once") {
				t.Fatalf("duplicate Set(%q) error = %v", value, err)
			}
		})
	}
	invalid := []string{"", "+1", "-1", "01", "1 ", "1_0", "4294967295", "4294967296"}
	if strconv.IntSize < 64 {
		invalid = append(invalid, "2147483648", "4294967294")
	}
	for _, value := range invalid {
		t.Run("invalid "+strconv.Quote(value), func(t *testing.T) {
			var flag identitySequenceHighWaterFlag
			if err := flag.Set(value); err == nil {
				t.Fatalf("Set(%q) succeeded", value)
			}
		})
	}
}

func TestRecoverIdentitySequenceRequiresRootTTYAndExactFlags(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		a, _, errb := newTestApp(t, "")
		a.Geteuid = func() int { return 1000 }
		a.StdinIsTTY = func() bool { t.Fatal("non-root request reached TTY check"); return true }
		if rc := a.Dispatch([]string{"recover-identity-sequence", "--highest", "1000"}); rc != 1 {
			t.Fatalf("non-root recovery rc = %d", rc)
		}
		if !strings.Contains(errb.String(), "please run as root") {
			t.Fatalf("non-root error = %q", errb.String())
		}
	})

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing highest", want: "--highest <historical-highest-ID> is required"},
		{name: "duplicate highest", args: []string{"--highest", "1000", "--highest", "1001"}, want: "only once"},
		{name: "noncanonical highest", args: []string{"--highest", "01000"}, want: "canonical decimal"},
		{name: "positional argument", args: []string{"--highest", "1000", "extra"}, want: "unexpected arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := newTestApp(t, "")
			a.StdinIsTTY = func() bool { t.Fatal("invalid flags reached TTY check"); return true }
			if rc := a.Dispatch(append([]string{"recover-identity-sequence"}, tc.args...)); rc != 1 {
				t.Fatalf("invalid recovery rc = %d", rc)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Fatalf("invalid recovery error missing %q: %q", tc.want, errb.String())
			}
		})
	}

	t.Run("TTY", func(t *testing.T) {
		a, _, errb := newTestApp(t, "RECOVER IDENTITY-SEQUENCE HIGHEST=1000\n")
		sequencePath := missingSequenceFixture(t, a, nil)
		a.StdinIsTTY = func() bool { return false }
		if rc := a.Dispatch([]string{"recover-identity-sequence", "--highest", "1000"}); rc != 1 {
			t.Fatalf("non-TTY recovery rc = %d", rc)
		}
		if !strings.Contains(errb.String(), "requires a real interactive terminal") {
			t.Fatalf("non-TTY error = %q", errb.String())
		}
		assertPathAbsent(t, sequencePath)
	})
}

func TestRecoverIdentitySequenceRejectsIneligibleAndLowStates(t *testing.T) {
	requireRootRegistryFixture(t)
	const generation = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *App) (sequencePath string, original []byte)
		high  string
		want  string
	}{
		{
			name: "healthy v5", high: "1000", want: "identity sequence is not missing",
			setup: func(t *testing.T, a *App) (string, []byte) {
				if err := a.Registry.Init(); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(a.Registry.Dir, "identity-sequence")
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return path, b
			},
		},
		{
			name: "corrupt sequence", high: "1000", want: "not eligible for missing-sequence recovery",
			setup: func(t *testing.T, a *App) (string, []byte) {
				if err := a.Registry.Init(); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(a.Registry.Dir, "identity-sequence")
				b := []byte("corrupt\n")
				if err := os.WriteFile(path, b, 0o600); err != nil {
					t.Fatal(err)
				}
				return path, b
			},
		},
		{
			name: "too-low sequence", high: "2000", want: "not eligible for missing-sequence recovery",
			setup: func(t *testing.T, a *App) (string, []byte) {
				rec := registry.Record{User: "xxvcc-recover-low-seq", UID: 1200, Generation: generation, IdentityBound: true, Port: 22}
				setTestRegistryRecord(t, a, rec)
				path := filepath.Join(a.Registry.Dir, "identity-sequence")
				b := []byte("# linux-temp-admin identity sequence v1\nhighest\t1100\nsafe-after\tnone\n")
				if err := os.WriteFile(path, b, 0o600); err != nil {
					t.Fatal(err)
				}
				return path, b
			},
		},
		{
			name: "legacy registry", high: "2000", want: "identity sequence is not missing",
			setup: func(t *testing.T, a *App) (string, []byte) {
				setLegacyV2RevokeRegistry(t, a, "xxvcc-recover-legacy", 9, 0, "")
				return filepath.Join(a.Registry.Dir, "identity-sequence"), nil
			},
		},
		{
			name: "below observed floor", high: "1499", want: "below the observed minimum 1500",
			setup: func(t *testing.T, a *App) (string, []byte) {
				return missingSequenceFixture(t, a, nil), nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := newTestApp(t, "RECOVER IDENTITY-SEQUENCE HIGHEST="+tc.high+"\n")
			a.StdinIsTTY = func() bool { return true }
			a.InspectIdentityAllocation = func() (user.IdentityAllocationSnapshot, error) {
				return user.IdentityAllocationSnapshot{Lower: 1000, Upper: 60000, CurrentHighest: 1500}, nil
			}
			path, original := tc.setup(t, a)
			if rc := a.Dispatch([]string{"recover-identity-sequence", "--highest", tc.high}); rc != 1 {
				t.Fatalf("ineligible recovery rc = %d", rc)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Fatalf("ineligible recovery error missing %q: %q", tc.want, errb.String())
			}
			if original == nil {
				assertPathAbsent(t, path)
			} else if current, err := os.ReadFile(path); err != nil || string(current) != string(original) {
				t.Fatalf("ineligible recovery changed sequence: bytes=%q err=%v", current, err)
			}
		})
	}
}

func TestRecoverIdentitySequenceRequiresExactConfirmation(t *testing.T) {
	requireRootRegistryFixture(t)
	a, _, errb := newTestApp(t, "recover identity-sequence highest=1500\n")
	sequencePath := missingSequenceFixture(t, a, nil)
	a.StdinIsTTY = func() bool { return true }
	a.InspectIdentityAllocation = func() (user.IdentityAllocationSnapshot, error) {
		return user.IdentityAllocationSnapshot{Lower: 1000, Upper: 60000, CurrentHighest: 1500}, nil
	}
	if rc := a.Dispatch([]string{"recover-identity-sequence", "--highest", "1500"}); rc != 0 {
		t.Fatalf("cancelled recovery rc = %d", rc)
	}
	if !strings.Contains(errb.String(), "RECOVER IDENTITY-SEQUENCE HIGHEST=1500") {
		t.Fatalf("confirmation prompt did not name the exact phrase: %q", errb.String())
	}
	assertPathAbsent(t, sequencePath)
}

func TestRecoverIdentitySequenceSuccessWarnsAndAuditsExactState(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		name       = "xxvcc-recover-success"
		generation = "0123456789abcdef0123456789abcdef"
	)
	now := time.Date(2026, 8, 16, 12, 0, 0, 500_000_000, time.UTC)
	a, out, errb := newTestApp(t, "RECOVER IDENTITY-SEQUENCE HIGHEST=2000\n")
	a.Now = func() time.Time { return now }
	sequencePath := missingSequenceFixture(t, a, &registry.Record{
		User: name, UID: 1200, Generation: generation, IdentityBound: true, Port: 22,
	})
	a.StdinIsTTY = func() bool { return true }
	a.InspectIdentityAllocation = func() (user.IdentityAllocationSnapshot, error) {
		return user.IdentityAllocationSnapshot{Lower: 1000, Upper: 2000, CurrentHighest: 1500}, nil
	}
	a.Lifecycle = lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	auditDir := t.TempDir()
	auditFile := filepath.Join(auditDir, "audit.log")
	a.Audit = &audit.Logger{
		Dir: auditDir, File: auditFile, Now: a.Now,
		Actor: func() (string, int) { return "release-test", 0 },
	}

	if rc := a.Dispatch([]string{"recover-identity-sequence", "--highest", "2000"}); rc != 0 {
		t.Fatalf("recovery rc = %d; stderr=%q", rc, errb.String())
	}
	if err := a.Registry.CheckIntegrity(); err != nil {
		t.Fatalf("recovered registry integrity: %v", err)
	}
	wantSafeAfter := time.Date(2026, 8, 16, 12, 1, 6, 0, time.UTC).Format(time.RFC3339)
	sequence, err := os.ReadFile(sequencePath)
	if err != nil {
		t.Fatal(err)
	}
	wantSequence := "# linux-temp-admin identity sequence v1\nhighest\t2000\nsafe-after\t" + wantSafeAfter + "\n"
	if string(sequence) != wantSequence {
		t.Fatalf("recovered sequence = %q, want %q", sequence, wantSequence)
	}
	fi, err := os.Stat(sequencePath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("recovered sequence mode = %o", fi.Mode().Perm())
	}
	if got := errb.String(); !strings.Contains(got, "cannot prove the highest UID/GID reserved") ||
		!strings.Contains(got, "reaches or exceeds the current allocation maximum") {
		t.Fatalf("recovery warnings incomplete: %q", got)
	}
	if got := out.String(); !strings.Contains(got, "identity sequence recovered: highest=2000") ||
		!strings.Contains(got, wantSafeAfter) {
		t.Fatalf("recovery success output incomplete: %q", got)
	}

	line, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Action string            `json:"action"`
		Result string            `json:"result"`
		Detail string            `json:"detail"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(line))), &event); err != nil {
		t.Fatal(err)
	}
	if event.Action != "registry.identity-sequence.recover" || event.Result != "ok" ||
		event.Detail != "missing identity sequence recovered" {
		t.Fatalf("recovery audit identity = %+v", event)
	}
	wantFields := map[string]string{
		"highest": "2000", "observed_floor": "1500", "registry_highest": "1200",
		"local_highest": "1500", "allocation_lower": "1000", "allocation_maximum": "2000",
		"safe_after": wantSafeAfter,
	}
	for key, want := range wantFields {
		if event.Fields[key] != want {
			t.Errorf("audit field %s = %q, want %q", key, event.Fields[key], want)
		}
	}
}

func TestRecoverIdentitySequenceRechecksStateAfterConfirmation(t *testing.T) {
	requireRootRegistryFixture(t)
	now := time.Date(2026, 8, 16, 13, 0, 0, 0, time.UTC)
	a, _, errb := newTestApp(t, "RECOVER IDENTITY-SEQUENCE HIGHEST=2000\n")
	a.Now = func() time.Time { return now }
	sequencePath := missingSequenceFixture(t, a, nil)
	a.StdinIsTTY = func() bool { return true }
	inspectCalls := 0
	a.InspectIdentityAllocation = func() (user.IdentityAllocationSnapshot, error) {
		inspectCalls++
		return user.IdentityAllocationSnapshot{
			Lower: 1000, Upper: 60000, CurrentHighest: 1000 + inspectCalls,
		}, nil
	}
	a.Lifecycle = lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	auditDir := t.TempDir()
	auditFile := filepath.Join(auditDir, "audit.log")
	a.Audit = &audit.Logger{Dir: auditDir, File: auditFile, Now: a.Now, Actor: func() (string, int) { return "test", 0 }}

	if rc := a.Dispatch([]string{"recover-identity-sequence", "--highest", "2000"}); rc != 1 {
		t.Fatalf("changed-state recovery rc = %d", rc)
	}
	if inspectCalls != 2 {
		t.Fatalf("allocation inspections = %d, want pre/post-confirmation reads", inspectCalls)
	}
	if !strings.Contains(errb.String(), "state changed") {
		t.Fatalf("changed-state error = %q", errb.String())
	}
	assertPathAbsent(t, sequencePath)

	b, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Action string            `json:"action"`
		Result string            `json:"result"`
		Detail string            `json:"detail"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &event); err != nil {
		t.Fatal(err)
	}
	if event.Action != "registry.identity-sequence.recover" || event.Result != "fail" ||
		!strings.Contains(event.Detail, "state changed") || event.Fields["observed_floor"] != "1002" {
		t.Fatalf("changed-state audit = %+v", event)
	}
}

func TestRecoverIdentitySequenceConfirmationDoesNotHoldLifecycleLock(t *testing.T) {
	requireRootRegistryFixture(t)
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	a, _, _ := newTestApp(t, "")
	a.Lifecycle = lifecycle.New(path)
	sequencePath := missingSequenceFixture(t, a, nil)
	a.StdinIsTTY = func() bool { return true }
	a.InspectIdentityAllocation = func() (user.IdentityAllocationSnapshot, error) {
		return user.IdentityAllocationSnapshot{Lower: 1000, Upper: 60000, CurrentHighest: 1000}, nil
	}
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	a.In = reader
	a.inReader = nil
	errOut := newNotifyingBuffer("Type RECOVER IDENTITY-SEQUENCE HIGHEST=1000 to confirm recovery")
	a.Err = errOut
	done := make(chan int, 1)
	go func() {
		done <- a.Dispatch([]string{"recover-identity-sequence", "--highest", "1000"})
	}()
	select {
	case <-errOut.seen:
	case <-time.After(2 * time.Second):
		t.Fatalf("recovery did not reach confirmation: %q", errOut.String())
	}

	release, err := lifecycle.New(path).TryAcquire()
	if err != nil {
		_, _ = io.WriteString(writer, "RECOVER IDENTITY-SEQUENCE HIGHEST=1000\n")
		<-done
		t.Fatalf("recovery held lifecycle lock while prompting: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "RECOVER IDENTITY-SEQUENCE HIGHEST=1000\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("recovery rc = %d; stderr=%q", rc, errOut.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not finish after confirmation")
	}
	if _, err := os.Stat(sequencePath); err != nil {
		t.Fatalf("recovery did not create sequence: %v", err)
	}
}

func TestRecoverIdentitySequenceHonorsUninstallTombstone(t *testing.T) {
	requireRootRegistryFixture(t)
	a, _, errb := newTestApp(t, "RECOVER IDENTITY-SEQUENCE HIGHEST=1000\n")
	sequencePath := missingSequenceFixture(t, a, nil)
	a.StdinIsTTY = func() bool { return true }
	a.InspectIdentityAllocation = func() (user.IdentityAllocationSnapshot, error) {
		return user.IdentityAllocationSnapshot{Lower: 1000, Upper: 60000, CurrentHighest: 1000}, nil
	}
	a.Lifecycle = lifecycle.New(filepath.Join(t.TempDir(), "lifecycle.lock"))
	if err := a.Lifecycle.MarkUninstalled(); err != nil {
		t.Fatal(err)
	}
	if rc := a.Dispatch([]string{"recover-identity-sequence", "--highest", "1000"}); rc != 1 {
		t.Fatalf("uninstalled recovery rc = %d", rc)
	}
	if !strings.Contains(errb.String(), "this tool is uninstalled") {
		t.Fatalf("uninstalled recovery error = %q", errb.String())
	}
	assertPathAbsent(t, sequencePath)
}

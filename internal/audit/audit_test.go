package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLogWritesJSONLines(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (audit dir must be root-owned)")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	l := &Logger{
		Dir:   dir,
		File:  file,
		Now:   func() time.Time { return time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC) },
		Actor: func() (string, int) { return "alice", 0 },
	}
	if err := l.Log(Event{Action: "account.create", Target: "xxvcc-a1", Result: "ok",
		Fields: map[string]string{"sudo": "yes"}}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Log(Event{Action: "account.delete", Target: "xxvcc-a1"}); err != nil { // default result "ok"
		t.Fatalf("Log 2: %v", err)
	}

	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 appended lines, got %d: %q", len(lines), b)
	}
	var rec record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if rec.Action != "account.create" || rec.Target != "xxvcc-a1" || rec.Result != "ok" ||
		rec.Actor != "alice" || rec.Fields["sudo"] != "yes" || rec.Time != "2026-07-08T12:00:00Z" {
		t.Errorf("unexpected record: %+v", rec)
	}
	var rec2 record
	if err := json.Unmarshal([]byte(lines[1]), &rec2); err != nil || rec2.Result != "ok" {
		t.Errorf("line 2 result should default to ok: %+v (err %v)", rec2, err)
	}
	if fi, _ := os.Lstat(file); fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("audit log mode = %v, want regular 0600", fi.Mode())
	}
}

func TestLogRepairsAndVerifiesExistingFileMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(file, []byte(""), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 12345, 12345); err != nil {
		// Some id-mapped/rootless test filesystems reject arbitrary numeric owners.
		// Mode repair is still exercised there; owner repair is exercised wherever
		// the filesystem supports constructing the unsafe fixture.
		t.Logf("cannot create non-root owner fixture: %v", err)
	}
	l := &Logger{Dir: dir, File: file, Now: time.Now, Actor: func() (string, int) { return "root", 0 }}
	if err := l.Log(Event{Action: "repair"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit type=%v owner=%d:%d mode=%o, want regular root:root 0600", fi.Mode(), st.Uid, st.Gid, fi.Mode().Perm())
	}
}

func TestLogRepairsIncompleteExistingTail(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	for _, tc := range []struct {
		name       string
		validFirst bool
		partialPad int
		want       []string
	}{
		{name: "after complete record", validFirst: true, want: []string{"before", "after"}},
		{name: "only incomplete record", want: []string{"after"}},
		{name: "newline beyond one scan block", validFirst: true, partialPad: (64 << 10) + 17, want: []string{"before", "after"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chown(dir, 0, 0); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "audit.log")
			l := &Logger{Dir: dir, File: file}
			var existing []byte
			if tc.validFirst {
				if err := l.Log(Event{Action: "before"}); err != nil {
					t.Fatal(err)
				}
				var err error
				existing, err = os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
			}
			existing = append(existing, `{"time":"crash","action":"partial"`...)
			existing = append(existing, strings.Repeat("x", tc.partialPad)...)
			if err := os.WriteFile(file, existing, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := l.Log(Event{Action: "after"}); err != nil {
				t.Fatal(err)
			}

			got, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
			if len(lines) != len(tc.want) {
				t.Fatalf("audit line count = %d, want %d: %q", len(lines), len(tc.want), got)
			}
			for i, line := range lines {
				var rec record
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("line %d is invalid JSON after recovery: %v: %q", i, err, line)
				}
				if rec.Action != tc.want[i] {
					t.Errorf("line %d action = %q, want %q", i, rec.Action, tc.want[i])
				}
			}
		})
	}
}

func TestLogRetryAfterTailRepairSyncFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	base := &Logger{Dir: dir, File: file}
	if err := base.Log(Event{Action: "before"}); err != nil {
		t.Fatal(err)
	}
	complete, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(append([]byte(nil), complete...), `{"partial":true`...), 0o600); err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("injected repaired-tail sync failure")
	failing := &Logger{Dir: dir, File: file, sync: func(*os.File) error { return wantErr }}
	if err := failing.Log(Event{Action: "not-appended"}); !errors.Is(err, wantErr) {
		t.Fatalf("Log error = %v, want repaired-tail sync failure", err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(complete) {
		t.Fatalf("failed repair sync did not leave the last complete boundary: got=%q want=%q", got, complete)
	}
	if err := base.Log(Event{Action: "retry"}); err != nil {
		t.Fatalf("retry Log: %v", err)
	}
	got, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit line count after repair retry = %d, want 2: %q", len(lines), got)
	}
}

func TestLogRejectsExistingNonRegularFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	if err := os.Mkdir(file, 0o700); err != nil {
		t.Fatal(err)
	}
	l := &Logger{Dir: dir, File: file, Now: time.Now, Actor: func() (string, int) { return "root", 0 }}
	if err := l.Log(Event{Action: "x"}); err == nil {
		t.Fatal("Log accepted a directory in place of a regular audit file")
	}
}

func TestLogRejectsFIFOWithoutBlocking(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	if err := unix.Mkfifo(file, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := (&Logger{Dir: dir, File: file}).Log(Event{Action: "x"})
	if err == nil || !strings.Contains(err.Error(), "not a safe regular file") {
		t.Fatalf("FIFO audit log error = %v, want special-file refusal", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("FIFO audit log blocked for %s", elapsed)
	}
}

func TestLogRefusesSymlinkTarget(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	_ = os.Chown(dir, 0, 0)
	_ = os.Chmod(dir, 0o700)
	file := filepath.Join(dir, "audit.log")
	if err := os.Symlink("/tmp/lta-audit-symlink-target", file); err != nil {
		t.Fatal(err)
	}
	l := &Logger{Dir: dir, File: file, Now: time.Now, Actor: func() (string, int) { return "x", 0 }}
	if err := l.Log(Event{Action: "x"}); err == nil {
		t.Error("Log must refuse a symlinked log path (O_NOFOLLOW)")
	}
}

func TestLogDisabledIsNoOp(t *testing.T) {
	var l *Logger // nil receiver
	if err := l.Log(Event{Action: "x"}); err != nil {
		t.Errorf("nil logger should be a no-op, got %v", err)
	}
	if err := (&Logger{}).Log(Event{Action: "x"}); err != nil { // empty paths => disabled
		t.Errorf("empty logger should be a no-op, got %v", err)
	}
}

func TestLogBoundsRecordAndTotalFileSize(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	l := &Logger{Dir: dir, File: file}
	if err := l.Log(Event{Action: "oversized", Detail: strings.Repeat("x", maxAuditRecordBytes)}); err == nil ||
		!strings.Contains(err.Error(), "audit record exceeds") {
		t.Fatalf("oversized record error = %v, want record-size refusal", err)
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Fatalf("oversized record created a log file: %v", err)
	}

	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(file, maxAuditLogBytes); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{'\n'}, maxAuditLogBytes-1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: "at-cap"}); err == nil || !strings.Contains(err.Error(), "archive or rotate") {
		t.Fatalf("full audit log error = %v, want total-size refusal", err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != maxAuditLogBytes {
		t.Fatalf("refused append changed audit size to %d, want %d", fi.Size(), maxAuditLogBytes)
	}

	if err := os.Truncate(file, maxAuditLogBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: "over-cap"}); err == nil || !strings.Contains(err.Error(), "archive or rotate") {
		t.Fatalf("oversized audit log error = %v, want pre-repair size refusal", err)
	}
	fi, err = os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != maxAuditLogBytes+1 {
		t.Fatalf("oversized audit log was scanned/repaired before refusal: size=%d", fi.Size())
	}
}

func TestLogRejectsFileOutsideDedicatedDirectoryWithoutMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	want := []byte("do not append\n")
	if err := os.WriteFile(victim, want, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&Logger{Dir: dir, File: victim}).Log(Event{Action: "outside"}); err == nil {
		t.Fatal("Logger accepted an audit file outside its dedicated directory")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("outside file content changed: %q", got)
	}
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("outside file mode changed to %o", fi.Mode().Perm())
	}
}

func TestLogRejectsHardLinkedFileWithoutMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "outside")
	want := []byte("outside content must not change\n")
	if err := os.WriteFile(victim, want, 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	if err := os.Link(victim, file); err != nil {
		t.Fatal(err)
	}

	err := (&Logger{Dir: dir, File: file}).Log(Event{Action: "hard-link"})
	if err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard-linked audit file error = %v, want shared-inode refusal", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("outside hard link content changed: %q", got)
	}
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("outside hard link mode changed to %o", fi.Mode().Perm())
	}
}

func TestLogRollsBackPartialWrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	base := &Logger{Dir: dir, File: file}
	if err := base.Log(Event{Action: "before"}); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	failed := false
	l := &Logger{Dir: dir, File: file}
	l.write = func(f *os.File, p []byte) (int, error) {
		if failed {
			return 0, errors.New("injected write failure")
		}
		failed = true
		n, err := f.Write(p[:len(p)/2])
		if err != nil {
			return n, err
		}
		return n, errors.New("injected write failure")
	}
	if err := l.Log(Event{Action: "partial"}); err == nil || !strings.Contains(err.Error(), "injected write failure") {
		t.Fatalf("Log error = %v, want injected write failure", err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("partial record was not rolled back:\n got %q\nwant %q", got, want)
	}
}

func TestLogSerializesConcurrentWriters(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "audit.log")
	const writers = 32
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- (&Logger{Dir: dir, File: file}).Log(Event{Action: "concurrent"})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != writers {
		t.Fatalf("audit line count = %d, want %d", len(lines), writers)
	}
	for i, line := range lines {
		var rec record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is partial or interleaved: %v: %q", i, err, line)
		}
	}
}

func TestLogReportsSyncFailureAfterCompleteLine(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l := &Logger{Dir: dir, File: filepath.Join(dir, "audit.log")}
	l.sync = func(*os.File) error { return errors.New("injected sync failure") }
	if err := l.Log(Event{Action: "complete"}); err == nil || !strings.Contains(err.Error(), "injected sync failure") {
		t.Fatalf("Log error = %v, want sync failure", err)
	}
	b, err := os.ReadFile(l.File)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"); len(lines) != 1 || !json.Valid([]byte(lines[0])) {
		t.Fatalf("sync failure left an incomplete audit record: %q", b)
	}
}

func TestLogRetriesDirectorySyncAfterFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	realSync := syncAuditDirectory
	t.Cleanup(func() { syncAuditDirectory = realSync })
	calls := 0
	wantErr := errors.New("injected audit directory sync failure")
	syncAuditDirectory = func(path string) error {
		calls++
		if calls == 1 {
			return wantErr
		}
		return realSync(path)
	}

	l := &Logger{Dir: dir, File: filepath.Join(dir, "audit.log")}
	if err := l.Log(Event{Action: "first"}); !errors.Is(err, wantErr) {
		t.Fatalf("first Log error = %v, want directory sync failure", err)
	}
	if err := l.Log(Event{Action: "retry"}); err != nil {
		t.Fatalf("retry Log: %v", err)
	}
	if calls != 2 {
		t.Fatalf("audit directory sync calls = %d, want retry after prior failure", calls)
	}

	b, err := os.ReadFile(l.File)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit line count after retry = %d, want 2: %q", len(lines), b)
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("audit line %d is invalid JSON after retry: %q", i, line)
		}
	}
}

func TestRealActor(t *testing.T) {
	t.Setenv("SUDO_USER", "bob")
	if a, _ := realActor(); a != "bob" {
		t.Errorf("actor with SUDO_USER = %q, want bob", a)
	}
	t.Setenv("SUDO_USER", "")
	if a, _ := realActor(); a != "root" {
		t.Errorf("actor without SUDO_USER = %q, want root", a)
	}
}

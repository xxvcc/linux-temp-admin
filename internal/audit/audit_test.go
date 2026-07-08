package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

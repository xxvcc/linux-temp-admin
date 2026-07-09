// Package audit appends a root-owned, append-only record of every privileged
// mutating operation (account create/delete, sudo grant, install/uninstall/
// upgrade) to a log file. Each entry is one JSON object per line and records
// when, who (the invoking user under sudo, plus the effective uid), what, the
// target, and the result — giving an operator-attributable trail.
//
// The log lives in a root-owned 0700 directory and is written 0600 with
// O_NOFOLLOW, so an unprivileged local user can neither read nor redirect it.
// Note: a root-level compromise can still tamper with an on-host log; forwarding
// to a remote collector (out of scope here) is what makes it tamper-evident.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

// Event is a single auditable operation, supplied by the caller.
type Event struct {
	Action string            // e.g. "account.create", "account.delete", "upgrade"
	Target string            // the affected username (empty for self-management)
	Result string            // "ok" or "fail"
	Detail string            // freeform note or error summary
	Fields map[string]string // optional structured params (host, sudo, auto, ...)
}

// record is the on-disk JSON shape.
type record struct {
	Time   string            `json:"time"`
	PID    int               `json:"pid"`
	Actor  string            `json:"actor"`
	UID    int               `json:"uid"`
	Action string            `json:"action"`
	Target string            `json:"target,omitempty"`
	Result string            `json:"result"`
	Detail string            `json:"detail,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Logger appends events to a file. Fields are injectable so tests can point at a
// temporary path and supply a fixed clock/actor.
type Logger struct {
	Dir   string
	File  string
	Now   func() time.Time
	Actor func() (actor string, uid int)
}

// Default returns a Logger writing to the configured audit-log path.
func Default() *Logger {
	return &Logger{Dir: config.AuditLogDir, File: config.AuditLogFile, Now: time.Now, Actor: realActor}
}

// realActor names the human behind the operation: the pre-sudo user when run via
// sudo, otherwise "root" (a direct-root run carries no further identity). The
// effective uid is reported alongside.
func realActor() (string, int) {
	euid := os.Geteuid()
	if su := os.Getenv("SUDO_USER"); su != "" {
		return su, euid
	}
	return "root", euid
}

// Log appends one event. It is best-effort from the caller's perspective (it
// returns any error so the caller can warn) but never partially writes: the JSON
// line is assembled in memory and written with a single append. A nil/empty-path
// Logger is a no-op, which disables auditing (e.g. in tests).
func (l *Logger) Log(ev Event) error {
	if l == nil || l.Dir == "" || l.File == "" {
		return nil
	}
	if err := fsutil.EnsureDir(l.Dir, 0o700, 0, 0); err != nil {
		return fmt.Errorf("audit dir: %w", err)
	}
	if err := fsutil.RootSafeDir(l.Dir); err != nil {
		return fmt.Errorf("audit dir unsafe: %w", err)
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	actor, uid := "root", os.Geteuid()
	if l.Actor != nil {
		actor, uid = l.Actor()
	}
	result := ev.Result
	if result == "" {
		result = "ok"
	}
	line, err := json.Marshal(record{
		Time:   now().UTC().Format(time.RFC3339),
		PID:    os.Getpid(),
		Actor:  actor,
		UID:    uid,
		Action: ev.Action,
		Target: ev.Target,
		Result: result,
		Detail: ev.Detail,
		Fields: ev.Fields,
	})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	// Append-only, refusing to follow a symlink planted at the path. A single
	// write of a bounded line is atomic under O_APPEND on a local filesystem.
	f, err := os.OpenFile(l.File, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	_ = f.Chown(0, 0) // enforce root:root if we just created it
	if _, err := f.Write(line); err != nil {
		return err
	}
	return nil
}

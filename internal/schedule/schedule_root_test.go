//go:build integration

package schedule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScheduleWritesSystemdUnits(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sys := &fakeSystem{hasSystemctl: true}
	s := newScheduler(dir, sys)

	unit, err := s.Schedule("xxvcc-a1", 24)
	if err != nil {
		t.Fatal(err)
	}
	if unit != "linux-temp-admin-v2-revoke-xxvcc-a1" {
		t.Errorf("unit = %q", unit)
	}
	svc, err := os.ReadFile(filepath.Join(dir, unit+".service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(svc), "ExecStart=/usr/local/sbin/linux-temp-admin revoke --user xxvcc-a1 --yes") {
		t.Errorf("service content:\n%s", svc)
	}
	tmr, err := os.ReadFile(filepath.Join(dir, unit+".timer"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tmr), "OnCalendar=2026-07-08 12:00:00 UTC") {
		t.Errorf("timer content:\n%s", tmr)
	}
	// daemon-reload and enable --now were called.
	var flat []string
	for _, c := range sys.calls {
		flat = append(flat, strings.Join(c, " "))
	}
	joined := strings.Join(flat, "|")
	if !strings.Contains(joined, "daemon-reload") || !strings.Contains(joined, "enable --now "+unit+".timer") {
		t.Errorf("systemctl calls = %v", sys.calls)
	}
}

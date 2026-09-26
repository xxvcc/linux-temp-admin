//go:build integration

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
)

func TestUninstallMenuStopsAfterVisibleRemoval(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failure     string
		wantRemoved bool
		wantStatus  int
		wantPrompts int
	}{
		{name: "success", wantRemoved: true, wantPrompts: 1},
		{name: "directory sync failure", failure: "after", wantRemoved: true, wantStatus: 1, wantPrompts: 1},
		{name: "unlink failure", failure: "before", wantStatus: 1, wantPrompts: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uninstallChoice, exitChoice := 0, 0
			for i, item := range menuItems {
				if item.en == "Uninstall" {
					uninstallChoice = i + 1
				}
				if item.run == nil {
					exitChoice = i + 1
				}
			}
			if uninstallChoice == 0 || exitChoice == 0 {
				t.Fatal("missing actual menu choices")
			}
			a, _, errb := uninstallApp(t, fmt.Sprintf("%d\nYES\n%d\n", uninstallChoice, exitChoice))
			calls := 0
			a.Selfmanage.RemoveFile = func(path string) error {
				calls++
				if path != a.InstallPath {
					t.Fatalf("unexpected remove path %s", path)
				}
				if tc.failure == "before" {
					return syscall.EIO
				}
				if err := fsutil.RemoveFile(path); err != nil {
					return err
				}
				if tc.failure == "after" {
					return &fsutil.DurabilityError{Operation: "unlink", Err: syscall.EIO}
				}
				return nil
			}
			status := a.menu()
			if status != tc.wantStatus || calls != 1 {
				t.Fatalf("status=%d remove calls=%d; %s", status, calls, errb)
			}
			_, err := os.Lstat(a.InstallPath)
			if removed := errors.Is(err, os.ErrNotExist); removed != tc.wantRemoved {
				t.Fatalf("removed=%v error=%v want=%v", removed, err, tc.wantRemoved)
			}
			prompt := fmt.Sprintf("select [1-%d] (Enter shows the menu): ", len(menuItems))
			if n := strings.Count(errb.String(), prompt); n != tc.wantPrompts {
				t.Fatalf("prompts=%d want=%d; %s", n, tc.wantPrompts, errb)
			}
			if tc.failure == "after" && !strings.Contains(errb.String(), "removal's durability is unknown") {
				t.Fatalf("missing visible-removal diagnostic: %s", errb)
			}
		})
	}
}

func TestStableInstallReportsVisibleDurabilityFailure(t *testing.T) {
	for _, tc := range []struct {
		name            string
		existing, write bool
	}{
		{"replacement", true, true}, {"first install", false, true}, {"before replacement", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := rootOwnedDir(t)
			a, _, _ := newTestApp(t, "")
			a.InstallPath = filepath.Join(dir, "linux-temp-admin")
			a.Selfmanage = selfmanage.New(a.InstallPath, config.MaxUpgradeBytes)
			old := []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 2.0.0\n")
			next := []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 0.0.0-dev\n")
			if tc.existing {
				if _, err := a.Selfmanage.Install(old, false); err != nil {
					t.Fatal(err)
				}
			}
			running := filepath.Join(dir, "running")
			if err := os.WriteFile(running, next, 0700); err != nil {
				t.Fatal(err)
			}
			a.Executable = func() (string, error) { return running, nil }
			logDir := filepath.Join(dir, "audit")
			logPath := filepath.Join(logDir, "audit.log")
			a.Audit = &audit.Logger{Dir: logDir, File: logPath, Now: a.Now, Actor: func() (string, int) { return "test", 0 }}
			calls := 0
			a.Selfmanage.WriteRootFile = func(path string, b []byte, mode os.FileMode) error {
				calls++
				if !tc.write {
					return syscall.EIO
				}
				if err := fsutil.WriteRootFile(path, b, mode); err != nil {
					return err
				}
				return &fsutil.DurabilityError{Operation: "rename", Err: syscall.EIO}
			}
			err := a.ensureStableInstalled()
			if !errors.Is(err, syscall.EIO) || calls != 1 {
				t.Fatalf("err=%v writes=%d", err, calls)
			}
			if a.stableCommandReplaced != (tc.existing && tc.write) {
				t.Fatalf("replacement report=%v", a.stableCommandReplaced)
			}
			want := old
			if tc.write {
				want = next
			}
			got, readErr := os.ReadFile(a.InstallPath)
			if readErr != nil || !bytes.Equal(got, want) {
				t.Fatalf("visible bytes differ: %v", readErr)
			}
			if tc.write {
				action := "installed"
				if tc.existing {
					action = "replaced"
				}
				logs, err := os.ReadFile(logPath)
				if err != nil || !bytes.Contains(logs, []byte("stable command "+action+" but durability unknown")) || !bytes.Contains(logs, []byte(`"result":"fail"`)) {
					t.Fatalf("missing committed install audit: %s %v", logs, err)
				}
			}
		})
	}
}

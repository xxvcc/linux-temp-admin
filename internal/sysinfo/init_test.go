package sysinfo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdBootEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, comm              string
		marker, booted, wantErr bool
	}{
		{name: "non-systemd init", comm: "openrc-init\n"},
		{name: "systemd init without marker", comm: "systemd\n", booted: true},
		{name: "booted marker", comm: "container-init\n", marker: true, booted: true},
		{name: "unreadable init", wantErr: true},
		{name: "empty init", comm: " \n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker, comm := filepath.Join(dir, "system"), filepath.Join(dir, "comm")
			if tc.marker {
				if err := os.Mkdir(marker, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.comm != "" {
				if err := os.WriteFile(comm, []byte(tc.comm), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			booted, err := systemdBooted(marker, comm)
			if booted != tc.booted || (err != nil) != tc.wantErr {
				t.Fatalf("booted=%v err=%v want booted=%v error=%v", booted, err, tc.booted, tc.wantErr)
			}
		})
	}
	t.Run("unqueryable marker is not absence", func(t *testing.T) {
		dir := t.TempDir()
		marker, comm := filepath.Join(dir, "marker"), filepath.Join(dir, "comm")
		if err := os.Symlink(marker, marker); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(comm, []byte("openrc-init\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if booted, err := systemdBooted(marker, comm); booted || err == nil {
			t.Fatalf("booted=%v err=%v want unknown evidence", booted, err)
		}
	})
}

func TestInitSystemDoesNotInferSystemdFromInstalledUtility(t *testing.T) {
	for _, tc := range []struct {
		name, other, want string
		booted            bool
		err               error
	}{
		{name: "binary without running systemd", want: "unknown"},
		{name: "openrc with systemctl installed", other: "rc-service", want: "openrc"},
		{name: "sysvinit with systemctl installed", other: "service", want: "sysvinit"},
		{name: "boot evidence", other: "rc-service", booted: true, want: "systemd"},
		{name: "unknown evidence", other: "service", err: errors.New("permission denied"), want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeSysinfoCommand(t, dir, "systemctl", "exit 0")
			if tc.other != "" {
				writeSysinfoCommand(t, dir, tc.other, "exit 0")
			}
			t.Setenv("PATH", dir)
			if got := initSystem(tc.booted, tc.err); got != tc.want {
				t.Fatalf("InitSystem=%q want %q", got, tc.want)
			}
		})
	}
}

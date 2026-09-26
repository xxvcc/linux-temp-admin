package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/sshkey"
)

func TestInviteSaveCommandCreatesPrivateFileWithoutClobber(t *testing.T) {
	const dummy = "dummy test credential\n"
	a, out, _ := newTestApp(t, "")
	if err := a.printInvite(inviteBundle{user: "xxvcc-save", kp: &sshkey.KeyPair{PrivatePEM: []byte(dummy)}}); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	start := strings.Index(rendered, "\n(\n")
	end := strings.Index(rendered, "\n)\n")
	if start < 0 || end <= start {
		t.Fatalf("save command missing: %s", rendered)
	}
	script := "umask 022\n" + rendered[start:end+3]
	for _, shell := range []string{"sh", "bash"} {
		if _, err := exec.LookPath(shell); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"new", "file", "symlink", "dangling symlink", "fifo"} {
			t.Run(shell+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				key := filepath.Join(dir, "xxvcc-save.key")
				target := filepath.Join(dir, "target")
				const old = "existing data\n"
				switch kind {
				case "file":
					if err := os.WriteFile(key, []byte(old), 0o644); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.WriteFile(target, []byte(old), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, key); err != nil {
						t.Fatal(err)
					}
				case "dangling symlink":
					if err := os.Symlink(target, key); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := syscall.Mkfifo(key, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, shell, "-c", script)
				cmd.Dir = dir
				output, err := cmd.CombinedOutput()
				if kind == "new" {
					if err != nil {
						t.Fatalf("save: %v: %s", err, output)
					}
					info, err := os.Stat(key)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != 0o600 {
						t.Fatalf("mode=%o", info.Mode().Perm())
					}
					data, err := os.ReadFile(key)
					if err != nil || string(data) != dummy {
						t.Fatalf("data=%q err=%v", data, err)
					}
				} else {
					if err == nil || ctx.Err() != nil {
						t.Fatalf("existing %s must fail promptly: err=%v context=%v", kind, err, ctx.Err())
					}
					switch kind {
					case "file", "symlink":
						data, err := os.ReadFile(key)
						if err != nil || string(data) != old {
							t.Fatalf("existing content changed: %q %v", data, err)
						}
					case "dangling symlink":
						if _, err := os.Lstat(target); !os.IsNotExist(err) {
							t.Fatalf("created dangling target: %v", err)
						}
					}
				}
			})
		}
	}
}

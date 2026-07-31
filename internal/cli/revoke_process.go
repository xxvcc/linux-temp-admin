package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/validate"
	"golang.org/x/sys/unix"
)

const (
	procReadBatch       = 256
	procCmdlineMaxBytes = int64(128 << 10)
	procStatusMaxBytes  = int64(64 << 10)
)

var errProcFileTooLarge = errors.New("process file exceeds read limit")

// runningLegacyRevokeProcess finds root-owned revoke processes emitted by
// releases that did not bind the command to an account generation. It is a
// migration guard, not deletion authority: a match only makes invite refuse to
// reuse the name until the old command has finished.
func runningLegacyRevokeProcess(procRoot, installPath, username string) (bool, error) {
	if procRoot == "" || installPath == "" {
		return false, fmt.Errorf("process inventory is not configured")
	}
	if !validate.Username(username) {
		return false, fmt.Errorf("invalid username %q", username)
	}
	proc, err := os.Open(procRoot)
	if err != nil {
		return false, fmt.Errorf("open process inventory: %w", err)
	}
	defer proc.Close()

	for {
		entries, readErr := proc.Readdirnames(procReadBatch)
		for _, entry := range entries {
			pid, parseErr := strconv.ParseUint(entry, 10, 31)
			if parseErr != nil || pid == 0 {
				continue
			}
			pidDir := filepath.Join(procRoot, entry)
			cmdline, cmdErr := readProcFile(filepath.Join(pidDir, "cmdline"), procCmdlineMaxBytes)
			if cmdErr != nil {
				if errors.Is(cmdErr, os.ErrNotExist) {
					continue
				}
				if !errors.Is(cmdErr, errProcFileTooLarge) {
					return false, fmt.Errorf("read process %s command line: %w", entry, cmdErr)
				}
			}
			argv := procArgv(cmdline)
			// A released direct revoke has five or eight short arguments, so an
			// oversized cmdline cannot be that exact argv. A shell invocation may
			// carry unrelated trailing arguments, however; its complete -c command
			// appears near the front and remains recognizable in the bounded prefix.
			directMatch := cmdErr == nil && legacyRevokeArgv(argv, installPath, username)
			if !directMatch && !legacyRevokeShellArgv(argv, installPath, username) {
				continue
			}
			status, statusErr := readProcFile(filepath.Join(pidDir, "status"), procStatusMaxBytes)
			if statusErr != nil {
				if errors.Is(statusErr, os.ErrNotExist) {
					continue
				}
				return false, fmt.Errorf("read process %s credentials: %w", entry, statusErr)
			}
			euid, uidErr := effectiveUID(status)
			if uidErr != nil {
				return false, fmt.Errorf("parse process %s credentials: %w", entry, uidErr)
			}
			if euid == 0 {
				return true, nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			return false, nil
		}
		if readErr != nil {
			return false, fmt.Errorf("read process inventory: %w", readErr)
		}
	}
}

func readProcFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return b[:limit], fmt.Errorf("%w: %s exceeds %d-byte limit", errProcFileTooLarge, path, limit)
	}
	return b, nil
}

func procArgv(cmdline []byte) []string {
	if len(cmdline) == 0 {
		return nil
	}
	parts := bytes.Split(cmdline, []byte{0})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	argv := make([]string, len(parts))
	for i := range parts {
		argv[i] = string(parts[i])
	}
	return argv
}

func legacyRevokeArgv(argv []string, installPath, username string) bool {
	if len(argv) != 5 && len(argv) != 8 {
		return false
	}
	if argv[0] != installPath || argv[1] != "revoke" || argv[2] != "--user" ||
		argv[3] != username || argv[4] != "--yes" {
		return false
	}
	return len(argv) == 5 ||
		(argv[5] == "--force" && argv[6] == "--confirm-force" && argv[7] == username)
}

func legacyRevokeShellArgv(argv []string, installPath, username string) bool {
	if len(argv) < 3 {
		return false
	}
	switch filepath.Base(argv[0]) {
	case "sh", "ash", "bash", "dash":
	default:
		return false
	}
	for i := 1; i+1 < len(argv); i++ {
		if argv[i] != "-c" {
			continue
		}
		command := strings.TrimSpace(argv[i+1])
		fields := strings.Fields(command)
		if command == strings.Join(fields, " ") && legacyRevokeArgv(fields, installPath, username) {
			return true
		}
	}
	return false
}

func effectiveUID(status []byte) (uint32, error) {
	found := false
	var euid uint32
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Uid:" {
			continue
		}
		if found || len(fields) != 5 {
			return 0, fmt.Errorf("invalid Uid field")
		}
		id, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid effective UID %q", fields[2])
		}
		euid = uint32(id)
		found = true
	}
	if !found {
		return 0, fmt.Errorf("missing Uid field")
	}
	return euid, nil
}

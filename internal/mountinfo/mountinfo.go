// Package mountinfo checks whether a recursive removal would cross a mount
// boundary described by Linux /proc mountinfo.
package mountinfo

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// RefuseUnder rejects root when it is itself a mountpoint or contains one.
// Recursive deletion must not cross into an independently mounted filesystem.
func RefuseUnder(root string) error {
	clean := filepath.Clean(root)
	if root == "" || !filepath.IsAbs(root) || clean != root {
		return fmt.Errorf("invalid recursive-removal root %q", root)
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("cannot inspect mount boundaries: %w", err)
	}
	defer f.Close()
	return RejectUnder(f, clean)
}

// RejectUnder applies the mount-boundary check to a supplied mountinfo stream.
func RejectUnder(r io.Reader, root string) error {
	cleanRoot := filepath.Clean(root)
	if root == "" || !filepath.IsAbs(root) || cleanRoot != root || cleanRoot == string(filepath.Separator) {
		return fmt.Errorf("invalid recursive-removal root %q", root)
	}
	if r == nil {
		return fmt.Errorf("nil mountinfo reader")
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	seen := false
	for sc.Scan() {
		seen = true
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			return fmt.Errorf("malformed mountinfo line")
		}
		if _, err := strconv.ParseUint(fields[0], 10, 64); err != nil {
			return fmt.Errorf("malformed mountinfo mount id %q", fields[0])
		}
		if _, err := strconv.ParseUint(fields[1], 10, 64); err != nil {
			return fmt.Errorf("malformed mountinfo parent id %q", fields[1])
		}
		device := strings.Split(fields[2], ":")
		if len(device) != 2 {
			return fmt.Errorf("malformed mountinfo device %q", fields[2])
		}
		for _, number := range device {
			if _, err := strconv.ParseUint(number, 10, 32); err != nil {
				return fmt.Errorf("malformed mountinfo device %q", fields[2])
			}
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) {
			return fmt.Errorf("malformed mountinfo separator")
		}
		if _, err := unescapePath(fields[3]); err != nil {
			return fmt.Errorf("malformed mountinfo root %q", fields[3])
		}
		mountpoint, err := unescapePath(fields[4])
		if err != nil || !canonicalAbsolute(mountpoint) {
			return fmt.Errorf("malformed mountinfo mountpoint %q", fields[4])
		}
		rel, err := filepath.Rel(cleanRoot, mountpoint)
		if err != nil {
			return fmt.Errorf("compare mountpoint %q: %w", mountpoint, err)
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return fmt.Errorf("refusing recursive removal across mountpoint %s", mountpoint)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read mount boundaries: %w", err)
	}
	if !seen {
		return fmt.Errorf("empty mountinfo stream")
	}
	return nil
}

func canonicalAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func unescapePath(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", fmt.Errorf("malformed mountinfo escape in %q", value)
		}
		escape := value[i+1 : i+4]
		if escape != "040" && escape != "011" && escape != "012" && escape != "134" {
			return "", fmt.Errorf("malformed mountinfo escape in %q", value)
		}
		n, err := strconv.ParseUint(escape, 8, 8)
		if err != nil {
			return "", fmt.Errorf("malformed mountinfo escape in %q", value)
		}
		out.WriteByte(byte(n))
		i += 3
	}
	return out.String(), nil
}

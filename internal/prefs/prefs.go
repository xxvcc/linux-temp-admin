// Package prefs remembers the operator's UI choices across runs — currently
// only the language.
//
// It is deliberately tiny and forgiving: a preference is a convenience, never a
// security decision, so every read failure degrades to "nothing remembered"
// rather than an error the caller has to handle. The file is written with the
// same root-owned, symlink-safe discipline as the tool's other state, because it
// lives beside the registry in a root-only directory.
package prefs

import (
	"os"
	"strings"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
)

// File is the preferences path; overridable in tests.
var File = config.PrefsFile

// langKey is the only key stored today. The format is key=value lines so a
// second preference can be added without a migration.
const langKey = "lang"

// Lang returns the remembered language selector ("zh"/"en"), or "" if none is
// remembered — the file is absent, unreadable, or has no language line. The
// caller validates the value; this package does not know what a language is.
func Lang() string {
	b, err := os.ReadFile(File)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == langKey {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// SetLang remembers lang for future runs. The value is written as-is, so callers
// must pass an already-validated selector.
func SetLang(lang string) error {
	if err := fsutil.EnsureDir(config.RegistryDir, 0o700, 0, 0); err != nil {
		return err
	}
	return fsutil.WriteRootFile(File, []byte(langKey+"="+lang+"\n"), 0o600)
}

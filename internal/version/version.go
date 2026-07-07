// Package version compares X.Y.Z[suffix] version strings, reproducing the bash
// version_gt semantics: numeric major/minor/patch, then a final release ranks
// above a prerelease (suffix), then suffixes compare lexicographically.
package version

import (
	"regexp"
	"strconv"
)

var re = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$`)

type parsed struct {
	major, minor, patch int
	suffix              string
	ok                  bool
}

func parse(v string) parsed {
	m := re.FindStringSubmatch(v)
	if m == nil {
		return parsed{}
	}
	maj, err1 := strconv.Atoi(m[1])
	min, err2 := strconv.Atoi(m[2])
	pat, err3 := strconv.Atoi(m[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return parsed{}
	}
	return parsed{major: maj, minor: min, patch: pat, suffix: m[4], ok: true}
}

// Greater reports whether newer is strictly greater than older. Either operand
// that does not parse as X.Y.Z[suffix] yields false (not comparable => not
// greater), matching version_gt's fail-closed behavior.
func Greater(newer, older string) bool {
	n := parse(newer)
	o := parse(older)
	if !n.ok || !o.ok {
		return false
	}
	if n.major != o.major {
		return n.major > o.major
	}
	if n.minor != o.minor {
		return n.minor > o.minor
	}
	if n.patch != o.patch {
		return n.patch > o.patch
	}
	// Equal core version: a final release outranks a prerelease suffix.
	if n.suffix == "" && o.suffix != "" {
		return true
	}
	if n.suffix != "" && o.suffix == "" {
		return false
	}
	// Both final or both prereleases: lexicographic (matches bash [[ > ]]).
	return n.suffix > o.suffix
}

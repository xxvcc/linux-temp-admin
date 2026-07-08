// Package version compares X.Y.Z[suffix] version strings, reproducing the bash
// version_gt semantics: numeric major/minor/patch, then a final release ranks
// above a prerelease (suffix), then suffixes compare lexicographically.
package version

import (
	"regexp"
	"strconv"
	"strings"
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
	// Both final or both prereleases: compare naturally so embedded numbers order
	// numerically (rc10 > rc9), not byte-lexicographically (which ranked "rc9" above
	// "rc10" and would let a signed older prerelease pass the not-newer upgrade gate).
	return naturalCompare(n.suffix, o.suffix) > 0
}

// naturalCompare orders two strings so that runs of digits compare by numeric value
// (with leading zeros ignored) and everything else compares byte-wise. It returns
// -1, 0, or 1. This gives "-rc2" < "-rc10" while keeping a stable total order.
func naturalCompare(a, b string) int {
	ia, ib := 0, 0
	for ia < len(a) && ib < len(b) {
		if isDigit(a[ia]) && isDigit(b[ib]) {
			ja, jb := ia, ib
			for ja < len(a) && isDigit(a[ja]) {
				ja++
			}
			for jb < len(b) && isDigit(b[jb]) {
				jb++
			}
			na := strings.TrimLeft(a[ia:ja], "0")
			nb := strings.TrimLeft(b[ib:jb], "0")
			if len(na) != len(nb) { // more significant digits => larger number
				if len(na) < len(nb) {
					return -1
				}
				return 1
			}
			if na != nb { // equal length: lexical order equals numeric order
				if na < nb {
					return -1
				}
				return 1
			}
			ia, ib = ja, jb
			continue
		}
		if a[ia] != b[ib] {
			if a[ia] < b[ib] {
				return -1
			}
			return 1
		}
		ia++
		ib++
	}
	switch { // the shorter remaining string sorts first
	case ia < len(a):
		return 1
	case ib < len(b):
		return -1
	default:
		return 0
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

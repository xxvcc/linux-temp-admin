// Package i18n parses a language selector and prints bilingual (zh/en) messages.
// Messages are supplied inline as (zh, en) pairs at the call site rather than via
// a keyed catalog.
//
// Precedence lives in the cli package, which owns the sources it draws on
// (--lang, the env override, the remembered preference, the operator). This
// package deliberately knows nothing about the host's locale: the language of the
// server says little about the language of the person holding the invite.
package i18n

import "strings"

// Lang is the resolved UI language.
type Lang string

const (
	ZH Lang = "zh"
	EN Lang = "en"
)

// Parse maps a locale/selector string to a language. It accepts zh*/cn* -> zh
// and en* -> en (case-insensitive); anything else is not a language.
func Parse(v string) (Lang, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(v, "zh"), strings.HasPrefix(v, "cn"):
		return ZH, true
	case strings.HasPrefix(v, "en"):
		return EN, true
	}
	return "", false
}

// Printer selects the active language for bilingual messages.
type Printer struct{ Lang Lang }

// M returns the zh or en string for the active language.
func (p Printer) M(zh, en string) string {
	if p.Lang == ZH {
		return zh
	}
	return en
}

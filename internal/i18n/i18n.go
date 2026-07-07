// Package i18n resolves the UI language and prints bilingual (zh/en) messages.
// It mirrors the bash tool: language precedence is explicit flag > env var >
// caller locale > English, and messages are supplied inline as (zh, en) pairs
// (the bash `m "<zh>" "<en>"` idiom) rather than via a keyed catalog.
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

// Resolve picks the language by precedence: flag, then env, then locale, then
// English. Empty/invalid values are skipped.
func Resolve(flag, env, locale string) Lang {
	for _, v := range []string{flag, env, locale} {
		if l, ok := Parse(v); ok {
			return l
		}
	}
	return EN
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

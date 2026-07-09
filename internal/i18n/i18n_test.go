package i18n

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Lang
		ok   bool
	}{
		{"zh", ZH, true},
		{"zh_CN.UTF-8", ZH, true},
		{"cn", ZH, true},
		{"en", EN, true},
		{"en_US.UTF-8", EN, true},
		{"EN", EN, true}, // case-insensitive
		{"fr", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Parse(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestResolvePrecedence(t *testing.T) {
	// flag wins over env and locale
	if got := Resolve("en", "zh", "zh_CN"); got != EN {
		t.Errorf("flag should win: got %q", got)
	}
	// env wins over locale when no flag
	if got := Resolve("", "zh", "en_US"); got != ZH {
		t.Errorf("env should win over locale: got %q", got)
	}
	// locale used when no flag/env
	if got := Resolve("", "", "zh_CN.UTF-8"); got != ZH {
		t.Errorf("locale should be used: got %q", got)
	}
	// an English locale still selects English
	if got := Resolve("", "", "en_US.UTF-8"); got != EN {
		t.Errorf("en locale should select en: got %q", got)
	}
	// default Chinese when nothing valid: no locale at all (the common server
	// case), and a locale in some third language.
	if got := Resolve("", "", ""); got != ZH {
		t.Errorf("default with no locale should be zh: got %q", got)
	}
	if got := Resolve("", "", "de_DE"); got != ZH {
		t.Errorf("default should be zh: got %q", got)
	}
}

func TestPrinterM(t *testing.T) {
	if got := (Printer{Lang: ZH}).M("你好", "hello"); got != "你好" {
		t.Errorf("zh M = %q", got)
	}
	if got := (Printer{Lang: EN}).M("你好", "hello"); got != "hello" {
		t.Errorf("en M = %q", got)
	}
}

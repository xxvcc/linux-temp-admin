package cli

import (
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/i18n"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/table"
)

func TestUsersViewFitsNarrowTerminal(t *testing.T) {
	a := &App{
		P:             i18n.Printer{Lang: i18n.EN},
		TerminalWidth: func() int { return 40 },
	}
	view := a.usersView([]registry.Record{{
		User: "lta-narrow", Sudo: true, AutoRevoke: true,
		Expires: "2026-07-26 13:55:46 UTC",
		Host:    strings.Repeat("host", 20) + ".example",
		Port:    2222,
	}}, true)
	if strings.Contains(view, "┌") {
		t.Fatalf("a table wider than the terminal was not changed to the compact view:\n%s", view)
	}
	for lineNo, line := range strings.Split(strings.TrimRight(view, "\n"), "\n") {
		if width := table.Width(line); width > 40 {
			t.Errorf("line %d is %d columns wide, want <= 40: %q", lineNo+1, width, line)
		}
	}
	for _, want := range []string{"1) lta-narrow", "state=missing", "sudo=yes", "auto-delete=yes", "port=2222"} {
		if !strings.Contains(view, want) {
			t.Errorf("compact view missing %q:\n%s", want, view)
		}
	}
}

func TestMenuLabelsFitFortyColumns(t *testing.T) {
	for i, item := range menuItems {
		for name, label := range map[string]string{"zh": item.zh, "en": item.en} {
			if width := 4 + table.Width(label); width > 40 {
				t.Errorf("menu item %d %s label is %d columns wide, want <= 40: %q", i+1, name, width, label)
			}
		}
	}
}

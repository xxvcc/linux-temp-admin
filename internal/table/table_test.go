package table

import (
	"strings"
	"testing"
)

func TestWidth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"xxvcc-a1b2c3", 12},
		{"在册", 4},  // two CJK runes, two columns each
		{"缺失", 4},  //
		{"是", 2},   //
		{"用户名", 6}, //
		{"a在b", 4}, // mixed
		{"2026-07-09 12:00:00 CST", 23},
		{"203.0.113.5", 11},
	}
	for _, c := range cases {
		if got := Width(c.in); got != c.want {
			t.Errorf("Width(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestRenderAlignsCJKColumns is the whole reason this package exists: fmt's
// width verbs pad by rune count, so a Chinese cell overflows its column and the
// vertical rules stop lining up. Every rendered line must be exactly as wide as
// the top border.
func TestRenderAlignsCJKColumns(t *testing.T) {
	tb := New("用户", "状态", "SUDO")
	tb.Row("xxvcc-a1b2c3", "在册", "是")
	tb.Row("xxvcc-d4e5f6", "缺失", "否")
	tb.Row("short", "missing", "no") // an English row in the same columns

	lines := strings.Split(strings.TrimRight(tb.String(), "\n"), "\n")
	want := Width(lines[0])
	for i, l := range lines {
		if got := Width(l); got != want {
			t.Errorf("line %d is %d columns wide, want %d (borders misaligned):\n%s", i, got, want, tb.String())
		}
	}
}

func TestRenderShape(t *testing.T) {
	tb := New("A", "B")
	tb.Row("1", "2")
	got := tb.String()
	for _, want := range []string{"┌", "┬", "┐", "├", "┼", "┤", "└", "┴", "┘", "│ A │ B │"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered table missing %q:\n%s", want, got)
		}
	}
	// The header rule must sit between the header and the first row.
	if strings.Index(got, "├") < strings.Index(got, "│ A │ B │") {
		t.Errorf("header separator is above the header:\n%s", got)
	}
}

// TestRowLengthMismatchCannotBreakBorders: a caller that miscounts cells must
// still get a well-formed table rather than ragged rules.
func TestRowLengthMismatchCannotBreakBorders(t *testing.T) {
	tb := New("A", "B", "C")
	tb.Row("only-one")         // too few
	tb.Row("1", "2", "3", "4") // too many
	lines := strings.Split(strings.TrimRight(tb.String(), "\n"), "\n")
	want := Width(lines[0])
	for i, l := range lines {
		if got := Width(l); got != want {
			t.Errorf("line %d width %d, want %d:\n%s", i, got, want, tb.String())
		}
	}
}

func TestEmpty(t *testing.T) {
	tb := New("A")
	if !tb.Empty() {
		t.Error("a table with no rows should report Empty")
	}
	tb.Row("x")
	if tb.Empty() {
		t.Error("a table with a row should not report Empty")
	}
}

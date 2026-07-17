// Package table renders box-drawn, column-aligned tables for the terminal.
//
// It exists because alignment cannot be done with fmt's width verbs here: %-8s
// pads to a count of runes, while a terminal lays out CJK characters two columns
// wide. A Chinese cell therefore comes out wider than its column, which merely
// looks untidy in key=value output but visibly breaks a box-drawn table — the
// vertical rules stop lining up. So padding is computed from display width.
//
// No third-party dependency: the tool ships as a single static binary with a
// deliberately tiny module graph, and a full Unicode width table would be far
// more than this needs. See Width for exactly what is covered and why that is
// enough for the data this tool prints.
package table

import (
	"io"
	"strings"
)

// Table accumulates a header and rows, then renders them aligned.
type Table struct {
	headers []string
	rows    [][]string
}

// New starts a table with the given column headers.
func New(headers ...string) *Table {
	return &Table{headers: headers}
}

// Row appends a row. A row with fewer cells than there are headers is padded
// with blanks; extra cells are ignored, so a caller can never make the borders
// ragged by miscounting.
func (t *Table) Row(cells ...string) {
	row := make([]string, len(t.headers))
	for i := range row {
		if i < len(cells) {
			row[i] = cells[i]
		}
	}
	t.rows = append(t.rows, row)
}

// Empty reports whether any rows were added.
func (t *Table) Empty() bool { return len(t.rows) == 0 }

// Render writes the table. Every column is as wide as its widest cell (header
// included), measured in terminal columns.
func (t *Table) Render(w io.Writer) {
	if len(t.headers) == 0 {
		return
	}
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = Width(h)
	}
	for _, row := range t.rows {
		for i, c := range row {
			if n := Width(c); n > widths[i] {
				widths[i] = n
			}
		}
	}

	io.WriteString(w, rule(widths, "┌", "┬", "┐"))
	io.WriteString(w, line(t.headers, widths))
	io.WriteString(w, rule(widths, "├", "┼", "┤"))
	for _, row := range t.rows {
		io.WriteString(w, line(row, widths))
	}
	io.WriteString(w, rule(widths, "└", "┴", "┘"))
}

// String renders the table into a string.
func (t *Table) String() string {
	var b strings.Builder
	t.Render(&b)
	return b.String()
}

// rule draws a horizontal border with the given corner/junction runes.
func rule(widths []int, left, mid, right string) string {
	var b strings.Builder
	b.WriteString(left)
	for i, w := range widths {
		if i > 0 {
			b.WriteString(mid)
		}
		b.WriteString(strings.Repeat("─", w+2)) // +2 for the single space each side
	}
	b.WriteString(right)
	b.WriteString("\n")
	return b.String()
}

// line draws one row of cells, each padded to its column's display width.
func line(cells []string, widths []int) string {
	var b strings.Builder
	b.WriteString("│")
	for i, c := range cells {
		b.WriteString(" ")
		b.WriteString(c)
		b.WriteString(strings.Repeat(" ", widths[i]-Width(c)))
		b.WriteString(" │")
	}
	b.WriteString("\n")
	return b.String()
}

// Width returns how many terminal columns s occupies.
//
// Scope, stated honestly: East Asian Wide and Fullwidth runes count as 2, every
// other rune as 1. That is exact for what this tool prints — its own zh/en
// labels, plus data that is ASCII by construction (usernames and prefixes are
// constrained to [a-z0-9_-] by validate, hosts to DNS/IP characters, and ports
// and dates to digits and punctuation). It does not model combining marks, zero
// width joiners, or emoji, none of which can reach a cell here. If a future
// caller feeds it arbitrary user text, this needs golang.org/x/text/width — do
// not let it silently under-measure.
func Width(s string) int {
	n := 0
	for _, r := range s {
		if isWide(r) {
			n += 2
			continue
		}
		n++
	}
	return n
}

// isWide reports whether r is East Asian Wide or Fullwidth.
func isWide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E,   // CJK radicals, Kangxi, CJK symbols
		r >= 0x3041 && r <= 0x33FF,   // kana, Hangul compat, CJK compat
		r >= 0x3400 && r <= 0x4DBF,   // CJK ext A
		r >= 0x4E00 && r <= 0x9FFF,   // CJK unified ideographs
		r >= 0xA000 && r <= 0xA4CF,   // Yi
		r >= 0xAC00 && r <= 0xD7A3,   // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF,   // CJK compat ideographs
		r >= 0xFE30 && r <= 0xFE6F,   // CJK compat forms, small forms
		r >= 0xFF00 && r <= 0xFF60,   // fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,   // fullwidth signs
		r >= 0x20000 && r <= 0x3FFFD: // CJK ext B and beyond
		return true
	}
	return false
}

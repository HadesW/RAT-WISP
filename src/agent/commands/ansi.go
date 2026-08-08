package commands

import (
	"regexp"
	"strings"
)

var (
	// CSI sequences: ESC [ params intermed final (colors, cursor, modes like ?1h).
	csiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")
	// OSC sequences: ESC ] ... BEL or ESC \ (title bar / hyperlinks).
	oscRe = regexp.MustCompile("\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)")
	// Charset selection: ESC ( B, ESC ) 0, ...
	charsetRe = regexp.MustCompile("\x1b[()][A-Z0-9]")
)

// stripANSI removes terminal control sequences (colors, cursor movement, title
// bar, charset selection) from shell output so it renders as clean text in the
// frontend console. Leftover lone ESC bytes are dropped as well.
func stripANSI(s string) string {
	s = oscRe.ReplaceAllString(s, "")
	s = csiRe.ReplaceAllString(s, "")
	s = charsetRe.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == 0x1b {
			return -1
		}
		return r
	}, s)
}

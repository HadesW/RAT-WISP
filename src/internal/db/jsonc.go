package db

// jsonc support for Malleable profiles. Standard encoding/json rejects
// comments, but operators naturally want to annotate their traffic-profile
// files. We accept a JSONC superset — `//` line comments and `/* */` block
// comments — and strip them before parsing. String literals are respected, so
// a comment marker inside a URL or User-Agent value is left untouched.

import "strings"

// stripJSONC removes line ("//") and block ("/* */") comments from a JSONC
// document while preserving string contents. It does not validate JSON; it only
// removes comment tokens that appear outside double-quoted strings.
func stripJSONC(src []byte) []byte {
	if len(src) == 0 {
		return src
	}
	var b strings.Builder
	b.Grow(len(src))

	inString := false
	inBlock := false
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case inBlock:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlock = false
				i += 2
				continue
			}
			i++
		case inString:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				// escaped char: copy the pair verbatim
				b.WriteByte(src[i+1])
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
		default:
			if c == '"' {
				inString = true
				b.WriteByte(c)
				i++
			} else if c == '/' && i+1 < len(src) && src[i+1] == '/' {
				// line comment: skip to end of line
				for i < len(src) && src[i] != '\n' {
					i++
				}
			} else if c == '/' && i+1 < len(src) && src[i+1] == '*' {
				inBlock = true
				i += 2
			} else {
				b.WriteByte(c)
				i++
			}
		}
	}
	return []byte(b.String())
}

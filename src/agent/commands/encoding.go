//go:build windows

package commands

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// decodeToUTF8 converts command output bytes to a UTF-8 string. Windows shells
// emit GBK (CP936) by default; try UTF-8 first and fall back to GBK so Chinese
// text round-trips to the frontend correctly.
func decodeToUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	if dec, err := simplifiedchinese.GBK.NewDecoder().Bytes(b); err == nil {
		return string(dec)
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// encodeToConsole converts UTF-8 text to the byte encoding expected by a
// Windows console (CP936). Used for stdin pipes; command-line arguments are
// passed as Unicode by Go and do not need this.
func encodeToConsole(s string) []byte {
	if utf8.ValidString(s) && !containsNonASCII(s) {
		return []byte(s)
	}
	if enc, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s)); err == nil {
		return enc
	}
	return []byte(s)
}

func containsNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

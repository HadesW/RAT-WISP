//go:build !windows

package commands

// decodeToUTF8 is a no-op on Unix where shells already emit UTF-8.
func decodeToUTF8(b []byte) string {
	return string(b)
}

// encodeToConsole passes text through unchanged on Unix.
func encodeToConsole(s string) []byte {
	return []byte(s)
}

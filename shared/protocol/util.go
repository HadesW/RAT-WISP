package protocol

import (
	"encoding/base64"
	"errors"
	"io"
	"regexp"
)

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func base64Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("protocol: empty data slot")
	}
	return base64.StdEncoding.DecodeString(s)
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		max = 4 << 20
	}
	return io.ReadAll(io.LimitReader(r, max))
}

var b64Re = regexp.MustCompile(`"([A-Za-z0-9+/]{40,}={0,2})"`)

func b64Tokens(body []byte) []string {
	m := b64Re.FindAllStringSubmatch(string(body), 16)
	out := make([]string, 0, len(m))
	for _, g := range m {
		out = append(out, g[1])
	}
	return out
}

//go:build !windows

package bof

import "fmt"

// Run is unsupported off-Windows (BOFs are x86/x64 machine code). The parser
// still works, so callers can validate objects cross-platform.
func Run(obj []byte, entrySym, arg string) (string, error) {
	if _, err := Parse(obj); err != nil {
		return "", err
	}
	return "", fmt.Errorf("BOF execution is only supported on Windows")
}

// DebugImports is unsupported off-Windows.
func DebugImports(obj []byte) (string, error) {
	img, err := Parse(obj)
	if err != nil {
		return "", err
	}
	var out string
	for _, s := range img.symbols {
		if s.importName != "" {
			out += fmt.Sprintf("import %-24s ptr=%v\n", s.importName, s.importPtr)
		}
	}
	return out, nil
}

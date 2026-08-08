package config

import (
	"bytes"
	"fmt"
	"os"

	"github.com/user/wisp/shared/protocol"
)

// loadOverlayConfig reads the config overlay appended to the end of the running
// module. For a standalone executable that is os.Executable(); for a DLL loaded
// by a host process it must be the DLL's own file (see selfpath_windows_cgo.go),
// because os.Executable() returns the host process's EXE path in that case.
func loadOverlayConfig() (string, error) {
	path, err := selfBinaryPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	idx := bytes.LastIndex(data, protocol.OverlayMarker)
	if idx < 0 {
		return "", fmt.Errorf("no overlay marker found")
	}
	return string(data[idx+len(protocol.OverlayMarker):]), nil
}

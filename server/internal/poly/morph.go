package poly

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// MorphPE produces a byte-different but functionally identical PE32+ build:
//
//   - TimeDateStamp (NT+8)
//   - section names (dot + per-section derived nibbles)
//   - the DOS-stub → NT gap when a Rich header lives there
//   - a random trailing overlay (skipped with NoOverlay or when the file ends
//     with a WISPEMB footer — subprocess loaders read the last 24 bytes)
//
// Section data, the WISPCFG slot and every header the loader consults stay
// untouched, so PatchBinary results and OS loading keep working.
func MorphPE(raw []byte, opt Options) ([]byte, error) {
	if len(raw) < 0x40 || raw[0] != 'M' || raw[1] != 'Z' {
		return nil, fmt.Errorf("poly: not a PE")
	}
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("poly: PE parse: %w", err)
	}
	if _, ok := f.OptionalHeader.(*pe.OptionalHeader64); !ok {
		return nil, fmt.Errorf("poly: only PE32+ is supported")
	}
	seedMat, err := seedMaterial(opt.Seed)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), raw...)
	nt := int(binary.LittleEndian.Uint32(out[0x3c:]))
	if nt < 0x40 || nt+4+20 > len(out) {
		return nil, fmt.Errorf("poly: bad NT offset")
	}

	// 1. timestamp
	d := derive(seedMat, 1)
	ts := binary.LittleEndian.Uint32(d[0:4])
	if ts == 0 {
		ts = 1
	}
	binary.LittleEndian.PutUint32(out[nt+8:], ts)

	// 2. section names
	optSize := int(binary.LittleEndian.Uint16(out[nt+4+16:]))
	nsec := int(binary.LittleEndian.Uint16(out[nt+4+2:]))
	secOff := nt + 24 + optSize
	if optSize >= 112 && nsec > 0 && nsec <= 96 && secOff+nsec*40 <= len(out) {
		for i := 0; i < nsec; i++ {
			s := derive(seedMat, byte(i+2))
			// ".r" + 6 hex chars derived from (section seed, index) → ≤ 8 bytes.
			name := []byte(fmt.Sprintf(".r%02x%02x%x", s[0], s[1], i%16))
			if len(name) > 8 {
				name = name[:8]
			}
			at := secOff + i*40
			for j := 0; j < 8; j++ {
				out[at+j] = 0
			}
			copy(out[at:], name)
		}
	}

	// 3. DOS/Rich gap between the DOS stub and the NT headers (only when the
	// config sentinel cannot be there — it lives in section data).
	if nt > 0x80 {
		sentinel := bytes.Index(out, []byte("WISPCFG\x01"))
		if sentinel < 0 || sentinel >= nt {
			k := derive(seedMat, 3)
			for j := 0x80; j < nt; j++ {
				out[j] = k[(j-0x80)%len(k)] ^ byte(j)
			}
		}
	}

	// 4. trailing overlay (appended data the loader ignores)
	if !opt.NoOverlay && !hasEmbeddedFooter(out) {
		k := derive(seedMat, 4)
		n := 16 + int(k[0])%49 // 16..64 bytes
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = k[i%len(k)] ^ byte(i*7)
		}
		out = append(out, buf...)
	}
	return out, nil
}

// hasEmbeddedFooter reports whether the file ends with the subprocess
// delivery footer (WISPEMB\x01) that loaders read at exactly file-24.
func hasEmbeddedFooter(b []byte) bool {
	const magic = "WISPEMB\x01"
	if len(b) < 24 {
		return false
	}
	return string(b[len(b)-8:]) == magic
}

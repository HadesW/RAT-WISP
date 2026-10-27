package protocol

// Payload config sentinel (plan §4): templates embed a fixed 4096-byte slot;
// the teamserver patches JSON into the slot at generation time — zero
// compilers needed at runtime.
//
// Slot layout:
//
//	magic "WISPCFG\x01" (8) | jsonLen u16 LE (2) | JSON (jsonLen) | zeros…
//
// Patching rewrites exactly CfgSlotSize bytes in place, keeping every binary
// byte offset intact (same-size replacement).

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
)

const (
	CfgSlotSize  = 4096
	cfgMagicLen  = 8
	cfgHeaderLen = cfgMagicLen + 2
)

// cfgMagic is only a search hint: the compiler can also emit these bytes as an
// instruction immediate. A marker alone must never identify a patchable slot.
func cfgMagic() []byte { return []byte{'W', 'I', 'S', 'P', 'C', 'F', 'G', 1} }

// PayloadCfg is the baked-in agent configuration (config.Config minus file).
type PayloadCfg struct {
	Servers      []string `json:"servers"`
	Path         string   `json:"path,omitempty"`
	Profile      *Profile `json:"profile,omitempty"` // baked traffic profile (plan P4)
	PSK          string   `json:"psk"`
	SleepMS      int      `json:"sleep_ms"`
	JitterPct    int      `json:"jitter_pct"`
	Insecure     bool     `json:"insecure,omitempty"`
	Staged       string   `json:"staged,omitempty"`        // stage URL; set only on stager payloads
	PluginPubkey string   `json:"plugin_pubkey,omitempty"` // hex ed25519 verifying key for dynamic plugins
}

// StagedSet marks a stager payload (carries only the stage URL + psk).
func (c PayloadCfg) StagedSet() bool { return c.Staged != "" }

var (
	ErrNoSlot        = errors.New("protocol: sentinel slot not found in binary")
	ErrBadSlot       = errors.New("protocol: malformed sentinel slot")
	ErrAmbiguousSlot = errors.New("protocol: multiple sentinel slots in binary")
)

// SentinelSlot is the compile-time literal present in every template's
// .data section (exported + referenced by config load so the linker keeps it).
var SentinelSlot = [CfgSlotSize]byte{0x57, 0x49, 0x53, 0x50, 0x43, 0x46, 0x47, 0x01}

// EncodeCfgSlot returns the full 4096-byte slot for the config.
func EncodeCfgSlot(cfg PayloadCfg) ([]byte, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if len(b) > CfgSlotSize-cfgHeaderLen {
		return nil, errors.New("protocol: payload config too large for slot")
	}
	slot := [CfgSlotSize]byte{}
	copy(slot[:cfgMagicLen], cfgMagic())
	binary.LittleEndian.PutUint16(slot[cfgMagicLen:cfgHeaderLen], uint16(len(b)))
	copy(slot[cfgHeaderLen:], b)
	return slot[:], nil
}

// FindCfgSlot decodes the unique complete config slot in a binary image,
// skipping incidental markers in code or other data. A slot must contain a
// bounded JSON payload followed by zero padding through the end of the slot.
// ok=false means "no marker"; err means no valid slot or multiple valid slots.
func FindCfgSlot(image []byte) (cfg PayloadCfg, ok bool, err error) {
	magic := cfgMagic()
	found, sawMarker := false, false
	for remaining := image; ; {
		off := bytes.Index(remaining, magic)
		if off < 0 {
			break
		}
		sawMarker = true
		candidate := remaining[off:]
		remaining = candidate[cfgMagicLen:]
		if len(candidate) < CfgSlotSize {
			continue
		}
		slot := candidate[:CfgSlotSize]
		n := int(binary.LittleEndian.Uint16(slot[cfgMagicLen:cfgHeaderLen]))
		if n == 0 || n > CfgSlotSize-cfgHeaderLen || !zeroPadding(slot[cfgHeaderLen+n:]) {
			continue
		}
		var decoded PayloadCfg
		if json.Unmarshal(slot[cfgHeaderLen:cfgHeaderLen+n], &decoded) != nil {
			continue
		}
		if found {
			return PayloadCfg{}, true, ErrAmbiguousSlot
		}
		cfg, found = decoded, true
	}
	if found {
		return cfg, true, nil
	}
	if sawMarker {
		return PayloadCfg{}, true, ErrBadSlot
	}
	return PayloadCfg{}, false, nil
}

// PatchBinary copies a template and replaces its unique empty reserved slot.
// Matching all 4096 bytes prevents a marker in machine code from being patched.
func PatchBinary(template []byte, cfg PayloadCfg) ([]byte, error) {
	slot, err := EncodeCfgSlot(cfg)
	if err != nil {
		return nil, err
	}
	off := bytes.Index(template, SentinelSlot[:])
	if off < 0 {
		return nil, ErrNoSlot
	}
	if bytes.Contains(template[off+CfgSlotSize:], SentinelSlot[:]) {
		return nil, ErrAmbiguousSlot
	}
	out := append([]byte(nil), template...)
	copy(out[off:off+CfgSlotSize], slot)
	return out, nil
}

func zeroPadding(padding []byte) bool {
	for _, b := range padding {
		if b != 0 {
			return false
		}
	}
	return true
}

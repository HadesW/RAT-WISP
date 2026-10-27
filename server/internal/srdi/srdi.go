// Package srdi turns a Windows DLL into position-independent shellcode.
//
// The bootstrap (loaders/srdi/bootstrap.cpp) is a reusable Windows x64
// template: it resolves Win32 from the PEB, maps an embedded DLL and calls one
// export. Reuse it by loading the prebuilt image once (LoadTemplate) and
// calling Build per artifact; the SRDICFG ABI below is the only coupling.
//
// The result is a 34-byte stub followed by a mapped copy of the bootstrap
// image, the DLL bytes and an optional parameter block. Nothing depends on a
// loader-assigned image base. Convert deliberately leaves the artifact
// unencrypted: transport encryption (Type4 AES-GCM per token) or a future
// poly/seal pass wraps these bytes without changing the bootstrap or this ABI.
package srdi

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"

	"wispp/server/internal/peimg"
)

const (
	// ABIVersion is stored in the bootstrap's SRDICFG and checked by both the
	// bootstrap and the Go assembler. Bump it when the layout below changes.
	ABIVersion = 1

	// Config layout shared with loaders/srdi/bootstrap.cpp.
	cfgMagic      = "SRDICFG\x01"
	cfgSize       = 100
	flagClearHdrs = 1

	stubLen = 34
	// objDLL marks IMAGE_FILE_DLL.
	objDLL = 0x2000
)

// Options selects the export and optional parameter block.
type Options struct {
	Export       string
	Params       []byte
	ClearHeaders bool
}

var (
	ErrNotPE       = errors.New("srdi: bootstrap is not a PE32+ image")
	ErrABI         = errors.New("srdi: unsupported bootstrap ABI")
	ErrNoSentinel  = errors.New("srdi: bootstrap has no SRDICFG sentinel")
	ErrAmbiguous   = errors.New("srdi: bootstrap has multiple SRDICFG sentinels")
	ErrImports     = errors.New("srdi: bootstrap must not import DLLs")
	ErrNotDLL      = errors.New("srdi: input is not a PE DLL")
	ErrExportName  = errors.New("srdi: export name must be ASCII and shorter than 64 bytes")
	ErrImageTooBig = errors.New("srdi: image exceeds the 32-bit RVAs used by the stub")
)

// Template is a parsed bootstrap image. It is immutable, so one Template can
// build any number of payloads, including concurrently.
type Template struct {
	image    []byte
	entryRVA uint32
	cfgRVA   uint32
}

// LoadTemplate maps and validates a bootstrap PE once.
func LoadTemplate(bootstrap []byte) (*Template, error) {
	image, entryRVA, err := mapBootstrap(bootstrap)
	if err != nil {
		return nil, err
	}
	cfgOff := bytes.Index(image, []byte(cfgMagic))
	if cfgOff < 0 {
		return nil, ErrNoSentinel
	}
	if bytes.Contains(image[cfgOff+len(cfgMagic):], []byte(cfgMagic)) {
		return nil, ErrAmbiguous
	}
	if cfgOff+cfgSize > len(image) {
		return nil, ErrNoSentinel
	}
	if got := binary.LittleEndian.Uint32(image[cfgOff+8:]); got != ABIVersion {
		return nil, fmt.Errorf("%w: bootstrap has %d, want %d", ErrABI, got, ABIVersion)
	}
	return &Template{image: image, entryRVA: entryRVA, cfgRVA: uint32(cfgOff)}, nil
}

// Convert is the one-shot form of LoadTemplate + Build.
func Convert(bootstrap, dll []byte, opt Options) ([]byte, error) {
	t, err := LoadTemplate(bootstrap)
	if err != nil {
		return nil, err
	}
	return t.Build(dll, opt)
}

// Build assembles stub + bootstrap image + dll + params.
func (t *Template) Build(dll []byte, opt Options) ([]byte, error) {
	export := opt.Export
	if export == "" {
		export = "WispStartEx"
	}
	if len(export) >= 64 {
		return nil, ErrExportName
	}
	for i := 0; i < len(export); i++ {
		if export[i] < 0x20 || export[i] > 0x7e {
			return nil, ErrExportName
		}
	}
	if err := checkDLL(dll); err != nil {
		return nil, err
	}

	imageSize := len(t.image)
	dllOff := align16(imageSize)
	paramsOff := 0
	if len(opt.Params) > 0 {
		paramsOff = align16(dllOff + len(dll))
	}
	if uint64(dllOff)+uint64(len(dll)) > uint64(^uint32(0)) ||
		uint64(paramsOff) > uint64(^uint32(0)) {
		return nil, ErrImageTooBig
	}
	total := stubLen + dllOff + len(dll)
	if len(opt.Params) > 0 {
		total = stubLen + paramsOff + len(opt.Params)
	}
	out := make([]byte, total)
	copy(out, peimg.JumpStub(t.entryRVA, t.cfgRVA))
	copy(out[stubLen:], t.image)

	flags := uint32(0)
	if opt.ClearHeaders {
		flags = flagClearHdrs
	}
	cfg := out[stubLen+t.cfgRVA : stubLen+t.cfgRVA+cfgSize]
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(cfg[at:], v) }
	put32(8, ABIVersion)
	put32(12, uint32(imageSize))
	put32(16, uint32(dllOff))
	put32(20, uint32(len(dll)))
	put32(24, uint32(paramsOff))
	put32(28, uint32(len(opt.Params)))
	put32(32, flags)
	copy(cfg[36:100], export)

	copy(out[stubLen+dllOff:], dll)
	if len(opt.Params) > 0 {
		copy(out[stubLen+paramsOff:], opt.Params)
	}
	return out, nil
}

// mapBootstrap delegates to peimg (shared with the poly decoder) and maps
// its errors onto the srdi vocabulary.
func mapBootstrap(raw []byte) ([]byte, uint32, error) {
	image, entry, err := peimg.Map(raw)
	if err != nil {
		if errors.Is(err, peimg.ErrImports) {
			return nil, 0, ErrImports
		}
		return nil, 0, ErrNotPE
	}
	return image, entry, nil
}

func checkDLL(dll []byte) error {
	f, err := pe.NewFile(bytes.NewReader(dll))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotDLL, err)
	}
	defer f.Close()
	if f.FileHeader.Characteristics&objDLL == 0 || f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return ErrNotDLL
	}
	return nil
}

func align16(n int) int { return (n + 15) &^ 15 }

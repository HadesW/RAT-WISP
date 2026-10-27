# WISP++ C++ agent build (MSVC). Outputs -> bin\out, intermediates -> bin\temp.
# Usage:
#   .\build.ps1              # Release EXE x64 + x86 (default)
#   .\build.ps1 -Arch x64
#   .\build.ps1 -Kind dll    # exe | dll | svc
#   .\build.ps1 -Debug       # console debug build (CRT linked)
param(
    [ValidateSet('x64', 'x86')]
    [string]$Arch = 'x64',
    [ValidateSet('exe', 'dll', 'svc', 'debug')]
    [string]$Kind = 'exe',
    [switch]$Trace,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$outDir = Join-Path $root 'bin\out'
$tempDir = Join-Path $root "bin\temp\$Kind`_$Arch"

if ($Clean) {
    if (Test-Path (Join-Path $root 'bin\temp')) { Remove-Item -Recurse -Force (Join-Path $root 'bin\temp') }
    if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
}

New-Item -ItemType Directory -Force -Path $outDir, $tempDir | Out-Null

# ---- locate MSVC via vswhere ----
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw 'vswhere not found - install Visual Studio with C++ tools' }
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw 'Visual Studio C++ tools not found' }
Write-Host "VS: $vsPath"

# ---- import environment (cl.exe, rc.exe, link.exe on PATH) ----
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found under $vsPath" }
$envArch = if ($Arch -eq 'x64') { 'x64' } else { 'x86' }
$tmpBat = Join-Path $env:TEMP "wisp_vcvars_$envArch.bat"
$tmpEnv = Join-Path $env:TEMP "wisp_vcvars_$envArch.env"
@"
@echo off
call `"$vcvars`" $envArch >nul 2>&1
set
"@ | Set-Content -Path $tmpBat -Encoding ASCII
cmd /c "`"$tmpBat`" > `"$tmpEnv`""
Get-Content $tmpEnv | ForEach-Object {
    $i = $_.IndexOf('=')
    if ($i -gt 0) {
        $k = $_.Substring(0, $i)
        $v = $_.Substring($i + 1)
        Set-Item -Path "Env:$k" -Value $v
    }
}
Remove-Item $tmpBat, $tmpEnv -ErrorAction SilentlyContinue

# ---- sources (WISP++ subset; legacy Adaptix files stay unused) ----
$sources = @(
    'main.cpp', 'WispAgent.cpp', 'WispConfig.cpp', 'WispCrypto.cpp',
    'WispJson.cpp', 'WispHttp.cpp', 'WispRcp.cpp', 'WispPlugin.cpp', 'tweetnacl.c',
    'ApiLoader.cpp', 'ProcLoader.cpp', 'utils.cpp', 'Encoders.cpp',
    'crt.cpp', 'config.cpp'
)

# ---- flags ----
$common = @(
    '/nologo', '/c', '/std:c++14', '/Gy', '/GF', '/GR-',
    '/D', 'WIN32', '/D', '_WINDOWS',
    '/I', (Join-Path $root 'src')
)
if ($Kind -eq 'debug') {
    $common += @('/Od', '/Zi', '/D', 'DEBUG', '/D', '_CONSOLE', '/D', '_WISP_CRT_BUILD', '/MD')
}
else {
    $common += @(
        '/O1', '/Os', '/Ob2', '/GS-',
        '/D', 'NDEBUG', '/D', '_WISP_NOCRT', '/MT'
    )
    if ($Trace) { $common += @('/D', 'DEBUG') }
}

$defines = @()
$traceSuffix = if ($Trace) { '-trace' } else { '' }
$outName = switch ($Kind) {
    'exe'   { "wisp-agent-cpp-$Arch$traceSuffix.exe"; $defines += @() }
    'dll'   { "wisp-agent-cpp-$Arch.dll"; $defines += @('/D', 'BUILD_DLL') }
    'svc'   { "wisp-agent-cpp-$Arch-svc.exe"; $defines += @('/D', 'BUILD_SVC') }
    'debug' { "wisp-agent-cpp-debug-$Arch.exe"; $defines += @() }
}

# ---- compile ----
$objs = @()
foreach ($s in $sources) {
    $obj = Join-Path $tempDir ([IO.Path]::GetFileNameWithoutExtension($s) + '.obj')
    $args = $common + $defines + @('/Fo' + $obj) + @((Join-Path $root "src\$s"))
    Write-Host "cl $s"
    & cl @args
    if ($LASTEXITCODE -ne 0) { throw "compile failed: $s" }
    $objs += $obj
}

# ---- link (no-CRT: entry depends on -Kind) ----
$outPath = Join-Path $outDir $outName
$machine = if ($Arch -eq 'x64') { 'X64' } else { 'X86' }
if ($Trace) {
    $subsystem = '/SUBSYSTEM:CONSOLE'
    $entry = '/ENTRY:main'
}
elseif ($Kind -eq 'dll') {
    $subsystem = '/SUBSYSTEM:WINDOWS'
    $entry = '/ENTRY:DllMain'
}
elseif ($Kind -eq 'svc') {
    $subsystem = '/SUBSYSTEM:CONSOLE'
    $entry = '/ENTRY:main'
}
else {
    $subsystem = '/SUBSYSTEM:WINDOWS'
    $entry = '/ENTRY:WinMain'
}
$linkArgs = @(
    '/nologo', ('/OUT:' + $outPath),
    $subsystem, '/DYNAMICBASE:NO', '/NXCOMPAT:NO',
    ('/MACHINE:' + $machine)
)
if ($Kind -eq 'debug') {
    $linkArgs += @('/SUBSYSTEM:CONSOLE', '/DEBUG')
    & link @linkArgs @objs bcrypt.lib
}
else {
    $linkArgs += @('/NODEFAULTLIB', $entry, '/MERGE:.rdata=.text', '/IGNORE:4210,4013')
    $libs = @('kernel32.lib')
    if ($Kind -eq 'dll') { $linkArgs += '/DLL' }
    if ($Kind -eq 'svc') { $libs += 'advapi32.lib' }
    if ($Arch -eq 'x86') {
        # x86 no-CRT: alias the compiler's helper calls to our crt.cpp impls.
        # 64-bit div/rem helpers are callee-cleanup (ret 16), so ours are
        # __stdcall -> symbol `___name@16`. The double<->int64 helpers use
        # MSVC's x86 SSE2 register ABI, which we reproduce with __vectorcall
        # -> decorated `name@@8`.
        $linkArgs += @(
            '/alternatename:__allmul=___allmul@16',
            '/alternatename:__allshl=___allshl',
            '/alternatename:__aullshr=___aullshr',
            '/alternatename:__allshr=___allshr',
            '/alternatename:__aulldiv=___aulldiv@16',
            '/alternatename:__aullrem=___aullrem@16',
            '/alternatename:__alldiv=___alldiv@16',
            '/alternatename:__allrem=___allrem@16',
            '/alternatename:__dtol3=__wisp_dtol3@@8',
            '/alternatename:__dtoul3_legacy=__wisp_dtoul3@@8',
            '/alternatename:__ltod3=__wisp_ltod3@@8',
            '/alternatename:__ultod3=__wisp_ultod3@@8'
        )
    }
    & link @linkArgs @objs @libs
    # drop the import-library byproducts (not needed for the agent)
    $base = [IO.Path]::GetFileNameWithoutExtension($outName)
    Remove-Item (Join-Path $outDir ($base + '.lib')) -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $outDir ($base + '.exp')) -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $outDir ($base + '.pdb')) -ErrorAction SilentlyContinue
}
if ($LASTEXITCODE -ne 0) { throw 'link failed' }

$size = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
Write-Host ""
Write-Host "OK: bin\out\$outName ($size KB)" -ForegroundColor Green

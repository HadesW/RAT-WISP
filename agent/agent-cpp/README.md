# C++ Agent (WISP++) — Update Summary

## What was updated
- Reorganized `agent/agent-cpp`: sources in `src/`, outputs in `bin/out`,
  intermediates in `bin/temp`; `bin/` is git-ignored.
- Implemented the WISP++ v2 protocol natively in C++ (MSVC/MinGW):
  - `WispJson` — JSON build/parse, CRT-free in release.
  - `WispCrypto` — CNG: RSA-OAEP(SHA-256) session-key wrap,
    AES-256-CTR + HMAC-SHA256 sealing, PSK proof, PEM/DER.
  - `WispConfig` — 4096-byte `WISPCFG\x01` sentinel slot or dev
    `-config <file>` (servers, psk, sleep_ms, jitter_pct, insecure).
  - `WispHttp` — WinINet POST, camo-404 handling, multi-server failover.
  - `WispAgent` — register/checkin/result loop, re-register after 3 misses.
  - Tasks: `shell`, `sysinfo`, `pwd`, `ls`, `mkdir`, `rm`, `ps`, `sleep`,
    `exit`/`kill`.
- Extended runtime API resolution (`ApiLoader`/`ApiDefines`); rewrote
  `main.cpp`/`main.h`.
- Build system: `build.ps1`, `Makefile`, `.vcxproj`/`.sln`.
  All variants build: `exe|dll|svc|debug` × `x64|x86`.
  Release sizes: x64 34.5 KB, x86 29 KB; exactly one sentinel slot.

## Verified
Against the local teamserver (dev-http :9000, API :9001), x86 and x64
release agents:
- register (PSK proof + wrapped session key), stay online, send sealed checkins;
- execute server tasks and return `ok`/`exit`/`output` results;
- `exit` terminates cleanly.

Latest run: 11 tasks across x86/x64 (sysinfo, pwd, ls, mkdir, rm, shell, ps,
sleep, exit) — all `completed`, `ok=true`, 0 failures.

## Build and run
    .\build.ps1 -Kind exe   -Arch x64
    .\build.ps1 -Kind debug -Arch x86
    .\build.ps1 -Kind exe   -Arch x86 -Trace
    .\bin\out\wisp-agent-cpp-x86.exe -config ..\..\data\agent-http.json

Server: `server\bin\wispd.exe -data data -templates server\templates -static client\dist`

## How to debug
- `-Kind debug`: CRT console build; stderr logs from `WLOG/WCLOG/WLOGCRYPT/WHLOG`
  (`[wisp]`, `[cfg]`, `[crypto]`, `[http]`).
- `-Trace`: no-CRT release build with the same logging (`-trace` suffix,
  console entry).
- Temporary probes used during bring-up: `WRAW` breadcrumbs, `WPTR` pointer
  logger, `WHV` heap validation.
- x86 ABI triage: `cl /FAs`, `dumpbin /disasm|/symbols` to inspect helper
  conventions and `ret N`.
- Server API: token in `data/api.token` (`X-Wisp-Token`);
  `GET /api/sessions`, `POST /api/sessions/{id}/tasks`, `GET /api/tasks`.
- Detached runs: `Start-Process -WindowStyle Hidden`; redirect stderr for
  debug/trace. PowerShell 5.1 has no ternary operator.

## Problems encountered and fixes
1. Heap corruption from `LocalReAlloc(LMEM_MOVEABLE)` → allocate-copy-free.
2. Protocol bugs: `BCRYPT_RSAPUBLIC_BLOB` is `"RSAPUBLICBLOB"`;
   `TaskResult.ok` must be a JSON bool; `cmd.exe` must be under
   `%WINDIR%\system32`; task `args` are borrowed and must not be freed.
3. x64 release link missed `_fltused`; x86 needed CRT math helpers.
4. x86 crash #1 — custom `_chkstk` only probed the stack, never allocated the
   frame; call arguments overwrote locals (e.g. the `cfg` pointer became hex
   text) → AV. Fixed with MSVC's algorithm: page probes, `xchg eax,esp`,
   relocate return address.
5. x86 crash #2 (no-CRT) — helper ABI mismatches:
   - `__dtol3`/`__dtoul3`: double in XMM0, result EDX:EAX → `__vectorcall`
     + `/alternatename`.
   - `__ltod3`/`__ultod3`: low in ECX, high in EDX, result XMM0 →
     `__vectorcall` (two u32 args).
   - `__aulldiv`/`__aullrem`/`__alldiv`/`__allrem`: callee-cleanup
     (`ret 16`) → `__stdcall` aliases. Mismatch caused ESP drift → AV in
     `WispEffectiveSleep`.
6. Build script: `dll`/`svc` used the exe entry (`WinMain`); DLL cleanup
   deleted the output DLL; `svc` missed `getServiceName`. Fixed with per-kind
   entry/subsystem, `advapi32` for `svc`, basename cleanup, `config.h` include.
7. Shell args are objects on the wire (`{"command":"..."}`); arrays yield
   `shell: empty command`.

## Not yet implemented
- Interactive RCP, SOCKS/port-forward, file transfer, plugins, screenshot.

## Notes
- Legacy Adaptix sources remain in `src/` but are not compiled by `build.ps1`.

#!/usr/bin/env bash
# Regenerates internal/stager/stager_blob.go from native/stager_stub.c.
# Requires gcc and python3. Run from the src/ directory.
set -euo pipefail
cd "$(dirname "$0")/.."

CC="${CC:-x86_64-w64-mingw32-gcc}"
$CC -m64 -ffreestanding -fno-pic -fno-stack-protector \
    -fno-asynchronous-unwind-tables -O1 \
    -c native/stager_stub.c -o /tmp/stager_stub.o
objcopy --only-section=.text -O binary /tmp/stager_stub.o /tmp/stager_stub.bin

# Locate stager_main symbol offset (entry point). The stub is compiled with the
# mingw64 Win64 ABI so every Windows API call uses RCX/RDX/R8/R9; the Go
# prologue must therefore pass &config in RCX (see internal/stager/stager.go).
ENTRY=$(nm -n /tmp/stager_stub.o | awk '$2=="T" && $3=="stager_main" {print $1}')

python3 - "$ENTRY" <<'PY'
import sys
entry = int(sys.argv[1], 16)
data = open('/tmp/stager_stub.bin', 'rb').read()
lines = ['\t' + ', '.join(f'0x{b:02x}' for b in data[i:i+16]) + ',' for i in range(0, len(data), 16)]
with open('internal/stager/stager_blob.go', 'w') as f:
    f.write('// Code generated from stager_stub.bin; DO NOT EDIT.\n')
    f.write('package stager\n\n')
    f.write('// stagerEntry is the byte offset of stager_main() within stagerBlob.\n')
    f.write(f'const stagerEntry = 0x{entry:x}\n')
    f.write('// stubLen is the size of the machine code (config block appended after).\n')
    f.write(f'const stubLen = {len(data)}\n')
    f.write('var stagerBlob = []byte{\n')
    f.write('\n'.join(lines))
    f.write('\n}\n')
PY

echo "regenerated internal/stager/stager_blob.go ($(stat -c%s /tmp/stager_stub.bin) bytes, entry=0x$ENTRY)"

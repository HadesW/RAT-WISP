#!/usr/bin/env bash
# Regenerates internal/srdi/srdi_blob.go from native/srdi_stub.c.
# Requires gcc and python3. Run from the src/ directory.
set -euo pipefail
cd "$(dirname "$0")/.."

CC="${CC:-x86_64-w64-mingw32-gcc}"
$CC -m64 -ffreestanding -fno-pic -fno-stack-protector \
    -fno-asynchronous-unwind-tables -O1 \
    -c native/srdi_stub.c -o /tmp/srdi_stub.o
objcopy --only-section=.text -O binary /tmp/srdi_stub.o /tmp/srdi_stub.bin

# Locate the stub_entry symbol offset (entry point).
ENTRY=$(nm -n /tmp/srdi_stub.o | awk '$2=="T" && $3=="stub_entry" {print $1}')

python3 - "$ENTRY" <<'PY'
import sys
entry = int(sys.argv[1], 16)
data = open('/tmp/srdi_stub.bin', 'rb').read()
lines = ['\t' + ', '.join(f'0x{b:02x}' for b in data[i:i+16]) + ',' for i in range(0, len(data), 16)]
with open('internal/srdi/srdi_blob.go', 'w') as f:
    f.write('// Code generated from srdi_stub.bin; DO NOT EDIT.\n')
    f.write('package srdi\n\n')
    f.write('// stubBlob is the position-independent reflective loader machine code\n')
    f.write('// produced from native/srdi_stub.c (see native/build_srdi.sh).\n')
    f.write('// stubEntry is the byte offset of stub_entry() within stubBlob.\n')
    f.write(f'const stubEntry = 0x{entry:x}\n')
    f.write('var stubBlob = []byte{\n')
    f.write('\n'.join(lines))
    f.write('\n}\n')
PY

echo "regenerated internal/srdi/srdi_blob.go ($(stat -c%s /tmp/srdi_stub.bin) bytes, entry=0x$ENTRY)"

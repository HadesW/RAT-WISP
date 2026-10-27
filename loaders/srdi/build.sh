#!/usr/bin/env bash
# Build the sRDI bootstrap image. The output is a normal PE file; the teamserver
# (server/internal/srdi) maps it to an in-memory image, patches the SRDICFG
# sentinel and prepends a position-independent jump stub.
#
# Requirements: no imports, no CRT — all Win32 entry points come from a PEB walk.
#
#   loaders/srdi/build.sh              # local build only
#   loaders/srdi/build.sh --install    # copy into server/templates
set -euo pipefail
cd "$(dirname "$0")/../.."

INSTALL=0
case "${1:-}" in
  --install) INSTALL=1 ;;
  "") ;;
  *) echo "usage: $0 [--install]" >&2; exit 2 ;;
esac

OUT_DIR=loaders/srdi/build
OUT="$OUT_DIR/srdi-bootstrap-x64.exe"

if [ -z "${CXX:-}" ]; then
  if [ -x .tools/mingw64/mingw64/bin/g++.exe ]; then
    CXX="$PWD/.tools/mingw64/mingw64/bin/g++.exe"
  elif command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
    CXX=x86_64-w64-mingw32-g++
  else
    echo "build-srdi: no x64 MinGW g++ found (set CXX=)" >&2
    exit 1
  fi
fi

mkdir -p "$OUT_DIR"
"$CXX" -std=c++23 -Os -s -flto -Wall -Wextra \
  -ffreestanding -fno-builtin -fno-stack-protector -fno-exceptions -fno-rtti -Wno-cast-function-type \
  -fno-tree-loop-distribute-patterns -nostdlib -mno-stack-arg-probe \
  -Iloaders/common \
  -Wl,--entry,srdi_entry -Wl,--subsystem,windows \
  -o "$OUT" loaders/srdi/bootstrap.cpp

size=$(wc -c <"$OUT")
echo "built $OUT (${size} bytes)"

if [ "$size" -gt 65536 ]; then
  echo "build-srdi: $OUT exceeds the 64 KB budget" >&2
  exit 1
fi

if ! grep -aq 'SRDICFG' "$OUT"; then
  echo "build-srdi: SRDICFG sentinel missing from $OUT" >&2
  exit 1
fi

OBJDUMP="${OBJDUMP:-$(dirname "$CXX")/objdump.exe}"
if [ -x "$OBJDUMP" ]; then
  if "$OBJDUMP" -p "$OUT" | grep -q 'DLL Name'; then
    echo "build-srdi: bootstrap must not import DLLs" >&2
    "$OBJDUMP" -p "$OUT" | grep 'DLL Name' >&2
    exit 1
  fi
  echo "no imports, sentinel present, budget ok"
fi

if [ "$INSTALL" = 1 ]; then
  dest=server/templates/srdi_bootstrap_windows_amd64.exe
  cp "$OUT" "$dest"
  sum=$(sha256sum "$dest" | cut -d' ' -f1)
  git_rev=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  dirty=false
  if [ -n "$(git status --porcelain -- loaders/srdi 2>/dev/null | head -1)" ]; then dirty=true; fi
  toolchain="$(basename "${CXX%.exe}") $("$CXX" -dumpversion)"
  cat >server/templates/srdi_manifest.json <<EOF
{
  "schema": 1,
  "kind": "srdi",
  "toolchain": "$toolchain",
  "source": "loaders/srdi/bootstrap.cpp",
  "git": "$git_rev",
  "dirty": $dirty,
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "files": [
    {"name": "srdi_bootstrap_windows_amd64.exe", "sha256": "$sum", "size": $(wc -c <"$dest")}
  ]
}
EOF
  echo "installed $dest + srdi_manifest.json"
fi
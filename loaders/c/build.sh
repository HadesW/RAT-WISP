#!/usr/bin/env bash
# Build the pure C x64 loader template. The output carries an empty 4096-byte
# WISPCFG slot; generation patches the stage URL in place (protocol.PatchBinary).
#
#   loaders/c/build.sh              # local build only
#   loaders/c/build.sh --install    # also copy into server/templates
#   CC=/path/to/x86_64-w64-mingw32-gcc loaders/c/build.sh
#
# Defaults to the cached MinGW toolchain under .tools/.
set -euo pipefail
cd "$(dirname "$0")/../.."

INSTALL=0
case "${1:-}" in
  --install) INSTALL=1 ;;
  "") ;;
  *) echo "usage: $0 [--install]" >&2; exit 2 ;;
esac

OUT_DIR=loaders/c/build
OUT="$OUT_DIR/loader-c-x64.exe"

if [ -z "${CC:-}" ]; then
  if [ -x .tools/mingw64/mingw64/bin/gcc.exe ]; then
    CC="$PWD/.tools/mingw64/mingw64/bin/gcc.exe"
  elif command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    CC=x86_64-w64-mingw32-gcc
  else
    echo "build-c-loader: no x64 MinGW gcc found (set CC=)" >&2
    exit 1
  fi
fi

mkdir -p "$OUT_DIR"
"$CC" -Os -s -Wall -Wextra -ffreestanding -fno-builtin -fno-stack-protector \
  -nostdlib -mno-stack-arg-probe \
  -Wl,--entry,loader_entry -Wl,--subsystem,windows \
  -o "$OUT" loaders/c/loader.c \
  -lwinhttp -lbcrypt -luser32 -lkernel32

size=$(wc -c <"$OUT")
echo "built $OUT (${size} bytes)"

if [ "$size" -gt 51200 ]; then
  echo "build-c-loader: $OUT exceeds the 50 KB budget" >&2
  exit 1
fi

if ! grep -aq 'WISPCFG' "$OUT"; then
  echo "build-c-loader: sentinel missing from $OUT" >&2
  exit 1
fi
echo "sentinel present, budget ok"

if [ "$INSTALL" = 1 ]; then
  dest=server/templates/loader_c_windows_amd64.exe
  cp "$OUT" "$dest"
  sum=$(sha256sum "$dest" | cut -d' ' -f1)
  git_rev=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  dirty=false
  if [ -n "$(git status --porcelain -- loaders/c 2>/dev/null | head -1)" ]; then dirty=true; fi
  toolchain="$(basename "${CC%.exe}") $("$CC" -dumpversion)"
  cat >server/templates/c_manifest.json <<EOF
{
  "schema": 1,
  "kind": "c",
  "toolchain": "$toolchain",
  "source": "loaders/c/loader.c",
  "git": "$git_rev",
  "dirty": $dirty,
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "files": [
    {"name": "loader_c_windows_amd64.exe", "sha256": "$sum", "size": $(wc -c <"$dest")}
  ]
}
EOF
  echo "installed $dest + c_manifest.json"
fi

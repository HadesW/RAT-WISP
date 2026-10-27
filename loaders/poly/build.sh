#!/usr/bin/env bash
# Build the poly decoder stub image (plan P5). Freestanding, no imports: the
# result is a template PE that server/internal/poly maps into encoded payloads.
#
#   loaders/poly/build.sh              # local build only
#   loaders/poly/build.sh --install    # copy into server/templates
set -euo pipefail
cd "$(dirname "$0")/../.."

INSTALL=0
case "${1:-}" in
  --install) INSTALL=1 ;;
  "") ;;
  *) echo "usage: $0 [--install]" >&2; exit 2 ;;
esac

OUT_DIR=loaders/poly/build
OUT="$OUT_DIR/poly-decoder-x64.exe"

if [ -z "${CC:-}" ]; then
  if [ -x .tools/mingw64/mingw64/bin/gcc.exe ]; then
    CC="$PWD/.tools/mingw64/mingw64/bin/gcc.exe"
  elif command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    CC=x86_64-w64-mingw32-gcc
  else
    echo "build-poly: no x64 MinGW gcc found (set CC=)" >&2
    exit 1
  fi
fi

mkdir -p "$OUT_DIR"
"$CC" -Os -s -Wall -Wextra \
  -ffreestanding -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -nostdlib -mno-stack-arg-probe \
  -Wl,--entry,poly_entry -Wl,--subsystem,windows \
  -o "$OUT" loaders/poly/decoder.c

size=$(wc -c <"$OUT")
echo "built $OUT (${size} bytes)"

if [ "$size" -gt 32768 ]; then
  echo "build-poly: $OUT exceeds the 32 KB budget" >&2
  exit 1
fi

if ! grep -aq 'POLYCFG' "$OUT"; then
  echo "build-poly: POLYCFG sentinel missing from $OUT" >&2
  exit 1
fi

OBJDUMP="${OBJDUMP:-$(dirname "$CC")/objdump.exe}"
if [ -x "$OBJDUMP" ]; then
  if "$OBJDUMP" -p "$OUT" | grep -q 'DLL Name'; then
    echo "build-poly: decoder must not import DLLs" >&2
    exit 1
  fi
  echo "no imports, sentinel present, budget ok"
fi

if [ "$INSTALL" = 1 ]; then
  dest=server/templates/poly_decoder_windows_amd64.exe
  cp "$OUT" "$dest"
  sum=$(sha256sum "$dest" | cut -d' ' -f1)
  git_rev=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  dirty=false
  if [ -n "$(git status --porcelain -- loaders/poly 2>/dev/null | head -1)" ]; then dirty=true; fi
  toolchain="$(basename "${CC%.exe}") $("$CC" -dumpversion)"
  cat >server/templates/poly_manifest.json <<EOF
{
  "schema": 1,
  "kind": "poly",
  "toolchain": "$toolchain",
  "source": "loaders/poly/decoder.c",
  "git": "$git_rev",
  "dirty": $dirty,
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "files": [
    {"name": "poly_decoder_windows_amd64.exe", "sha256": "$sum", "size": $(wc -c <"$dest")}
  ]
}
EOF
  echo "installed $dest + poly_manifest.json"
fi
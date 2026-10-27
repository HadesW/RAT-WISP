#!/usr/bin/env bash
# Build the C++23 x64 loader template. Like the pure-C loader, the output
# carries an empty 4096-byte WISPCFG slot; generation patches the stage URL.
#
#   loaders/cpp/build.sh              # local build only
#   loaders/cpp/build.sh --install    # also copy into server/templates
#   CXX=/path/to/g++ loaders/cpp/build.sh
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

OUT_DIR=loaders/cpp/build
OUT="$OUT_DIR/loader-cpp-x64.exe"

if [ -z "${CXX:-}" ]; then
  if [ -x .tools/mingw64/mingw64/bin/g++.exe ]; then
    CXX="$PWD/.tools/mingw64/mingw64/bin/g++.exe"
  elif command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
    CXX=x86_64-w64-mingw32-g++
  else
    echo "build-cpp-loader: no x64 MinGW g++ found (set CXX=)" >&2
    exit 1
  fi
fi

mkdir -p "$OUT_DIR"
"$CXX" -std=c++23 -Os -s -flto -Wall -Wextra \
  -fno-builtin -fno-stack-protector -fno-exceptions -fno-rtti -Wno-cast-function-type \
  -fno-tree-loop-distribute-patterns -nostdlib -mno-stack-arg-probe \
  -Iloaders/common \
  -Wl,--entry,loader_entry -Wl,--subsystem,windows \
  -o "$OUT" loaders/cpp/loader.cpp \
  -lwinhttp -lbcrypt -luser32 -lkernel32

size=$(wc -c <"$OUT")
echo "built $OUT (${size} bytes)"

if [ "$size" -gt 256000 ]; then
  echo "build-cpp-loader: $OUT exceeds the 250 KB budget" >&2
  exit 1
fi

if ! grep -aq 'WISPCFG' "$OUT"; then
  echo "build-cpp-loader: sentinel missing from $OUT" >&2
  exit 1
fi
echo "sentinel present, budget ok"

if [ "$INSTALL" = 1 ]; then
  dest=server/templates/loader_cpp_windows_amd64.exe
  cp "$OUT" "$dest"
  sum=$(sha256sum "$dest" | cut -d' ' -f1)
  git_rev=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  dirty=false
  if [ -n "$(git status --porcelain -- loaders/cpp 2>/dev/null | head -1)" ]; then dirty=true; fi
  toolchain="$(basename "${CXX%.exe}") $("$CXX" -dumpversion)"
  cat >server/templates/cpp_manifest.json <<EOF
{
  "schema": 1,
  "kind": "cpp",
  "toolchain": "$toolchain",
  "source": "loaders/cpp/loader.cpp",
  "git": "$git_rev",
  "dirty": $dirty,
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "files": [
    {"name": "loader_cpp_windows_amd64.exe", "sha256": "$sum", "size": $(wc -c <"$dest")}
  ]
}
EOF
  echo "installed $dest + cpp_manifest.json"
fi

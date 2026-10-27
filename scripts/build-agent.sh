#!/usr/bin/env bash
# Offline source-build entry point for agent templates (plan P1). There is no
# compiler on the teamserver: payload generation only patches prebuilt images.
#
# Examples:
#   scripts/build-agent.sh -agent go   -targets windows_amd64,windows_arm64 -format exe,dll -allow-dirty
#   scripts/build-agent.sh -agent rust -format exe,dll,stage -allow-dirty
#   scripts/build-agent.sh -agent all  -out server/templates -allow-dirty
#
# -format names: exe, svc, script, dll, stage (svc/script share the exe template;
# shellcode lands with the P2 sRDI work).
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
usage: scripts/build-agent.sh [-agent go|rust|all] [-targets os_arch,...]
                              [-format exe,stage,dll,svc,script]
                              [-out DIR] [-manifest FILE] [-allow-dirty]
EOF
}

AGENT=all
TARGETS=""
FORMATS=""
OUT=server/templates
MANIFEST=""
ALLOW_DIRTY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -agent|--agent) AGENT="${2:-}"; shift 2 ;;
    -targets|--targets|-target|--target) TARGETS="${2:-}"; shift 2 ;;
    -format|--format|-formats|--formats) FORMATS="${2:-}"; shift 2 ;;
    -out|--out) OUT="${2:-}"; shift 2 ;;
    -manifest|--manifest) MANIFEST="${2:-}"; shift 2 ;;
    -allow-dirty|--allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "build-agent: unknown argument '$1'" >&2; usage >&2; exit 1 ;;
  esac
done
case "$AGENT" in go|rust|all) ;; *) echo "build-agent: -agent must be go, rust or all" >&2; exit 1 ;; esac

TARGETS=$(printf '%s' "$TARGETS" | tr ',' ' ')
FORMATS=$(printf '%s' "$FORMATS" | tr ',' ' ')
[ -z "$TARGETS" ] && TARGETS="darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 linux_386 windows_amd64 windows_arm64 windows_386"

mkdir -p "$OUT"
OUT_ABS=$(cd "$OUT" && pwd)
abspath() { mkdir -p "$(dirname "$1")"; printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"; }
DIRTY=()
[ "$ALLOW_DIRTY" = "1" ] && DIRTY=(-allow-dirty)

append_format() {
  if [ -z "$1" ]; then printf '%s' "$2"; return; fi
  case ",$1," in
    *",$2,"*) printf '%s' "$1" ;;
    *) printf '%s,%s' "$1" "$2" ;;
  esac
}

GO_FORMATS=""
RS_FORMATS=""
if [ -z "$FORMATS" ]; then
  GO_FORMATS="exe,stage,dll"
  RS_FORMATS="agent,dll,staged"
else
  for f in $FORMATS; do
    case "$f" in
      exe) GO_FORMATS=$(append_format "$GO_FORMATS" exe) ;;
      svc)
        GO_FORMATS=$(append_format "$GO_FORMATS" exe)
        GO_FORMATS=$(append_format "$GO_FORMATS" svc)
        ;;
      script)
        GO_FORMATS=$(append_format "$GO_FORMATS" exe)
        GO_FORMATS=$(append_format "$GO_FORMATS" script)
        ;;
      stage)
        GO_FORMATS=$(append_format "$GO_FORMATS" stage)
        RS_FORMATS=$(append_format "$RS_FORMATS" staged)
        ;;
      dll)
        GO_FORMATS=$(append_format "$GO_FORMATS" dll)
        RS_FORMATS=$(append_format "$RS_FORMATS" dll)
        ;;
      shellcode) echo "build-agent: shellcode is P2 (sRDI bootstrap)" >&2; exit 1 ;;
      *) echo "build-agent: unknown format '$f'" >&2; exit 1 ;;
    esac
  done
fi

if [ "$AGENT" = "all" ] || [ "$AGENT" = "go" ]; then
  echo "== go: targets=[$TARGETS] formats=[$GO_FORMATS]"
  ARGS=(-agent go -targets "$TARGETS" -formats "$GO_FORMATS" -out "$OUT_ABS")
  if [ -n "$MANIFEST" ]; then ARGS+=(-manifest "$(abspath "$MANIFEST")"); fi
  (cd server && go run ./cmd/build_templates "${ARGS[@]}" "${DIRTY[@]}")
fi

if [ "$AGENT" = "all" ] || [ "$AGENT" = "rust" ]; then
  case " $TARGETS " in
    *" windows_amd64 "*) ;;
    *) echo "== rust: windows_amd64 not in targets — skipped (other Rust targets are built natively in CI)"; exit 0 ;;
  esac
  if [ -z "$RS_FORMATS" ]; then echo "== rust: no artifacts requested"; exit 0; fi
  echo "== rust: formats=[$RS_FORMATS]"
  WISP_RS_FORMATS="$RS_FORMATS" WISP_RS_OUT="$OUT_ABS" WISP_ALLOW_DIRTY="$ALLOW_DIRTY" \
    bash scripts/build-rs-templates.sh
  if [ -n "$MANIFEST" ] && [ "$AGENT" = "rust" ]; then
    cp "$OUT_ABS/rs_manifest.json" "$(abspath "$MANIFEST")"
  fi
fi

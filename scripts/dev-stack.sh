#!/usr/bin/env bash
# Persistent dev/demo stack: teamserver with NO default listeners (RAT-WISP
# style — operator creates them), then http:9000 / tcp:9100 / rcp:9200 via the
# API, then demo agents. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."
# In some Git-for-Windows shells `python3` resolves to the Microsoft Store
# stub (exit 49); probe before committing to it.
if python3 -c 'pass' >/dev/null 2>&1; then PY=python3; else PY=python; fi
# Payload templates are gitignored build artifacts. WISP_REBUILD_TEMPLATES=1
# rebuilds both families so generated payloads never carry stale agent code.
if [ "${WISP_REBUILD_TEMPLATES:-0}" = "1" ]; then
  echo "rebuilding payload templates (WISP_REBUILD_TEMPLATES=1) ..."
  (cd server && go run ./cmd/build_templates -out templates -allow-dirty) || exit 1
  WISP_ALLOW_DIRTY=1 bash scripts/build-rs-templates.sh || exit 1
fi
TEMPLATES=server/templates
HEAD_REV=$(git rev-parse --short=12 HEAD 2>/dev/null || echo "")
if [ ! -f "$TEMPLATES/agent_windows_amd64.exe" ]; then
  echo "warn: no agent templates in $TEMPLATES — run: (cd server && go run ./cmd/build_templates -out templates)" >&2
fi
for mf in go_manifest.json rs_manifest.json; do
  [ -f "$TEMPLATES/$mf" ] || continue
  MGIT=$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("git",""))' "$TEMPLATES/$mf" 2>/dev/null || true)
  if [ -n "$HEAD_REV" ] && [ -n "$MGIT" ] && [ "$MGIT" != "$HEAD_REV" ]; then
    echo "warn: $mf built from $MGIT, HEAD is $HEAD_REV — payloads use stale templates (set WISP_REBUILD_TEMPLATES=1)" >&2
  fi
done
(cd server && go build -o bin/wispd ./cmd/wispd) || exit 1
(cd agent/agent-go && go build -o ../bin/wisp-agent .) || exit 1
pkill -9 -f 'bin/wispd|bin/wisp-agent' 2>/dev/null || true
# MSYS pkill misses processes launched outside its tree; backstop on Windows.
if command -v taskkill >/dev/null 2>&1; then
  taskkill //IM wispd //F >/dev/null 2>&1 || true
  taskkill //IM wisp-agent.exe //F >/dev/null 2>&1 || true
  taskkill //IM wisp-agent //F >/dev/null 2>&1 || true
fi
sleep 0.5

# Launch via bash, not python: CreateProcess appends ".exe" to extensionless
# names, so Python cannot run the `.exe`-less Go outputs on Windows.
./server/bin/wispd -api 127.0.0.1:9001 -static client/dist -data data \
  -templates server/templates -ai-config data/ai.json -sleep 3000 -jitter 20 \
  > data-server.log 2>&1 &
sleep 2
TOKEN=$(cat data/api.token); PSK=$(cat data/psk.key)
H=(-H "X-Wisp-Token: $TOKEN" -H "Content-Type: application/json")
# idempotent fleet: skip names that already exist (Restore may have brought them)
EXISTING=$(curl -s "${H[@]}" http://127.0.0.1:9001/api/listeners | "$PY" -c 'import sys,json;print(" ".join(l["name"] for l in json.load(sys.stdin)))')
for spec in "dev-http|http|127.0.0.1:9000" "dev-tcp|tcp|127.0.0.1:9100" "dev-rcp|rcp|127.0.0.1:9200" "dev-kcp|kcp|127.0.0.1:9400" "dev-rcp-kcp|rcp-kcp|127.0.0.1:9500"; do
  IFS='|' read -r name kind addr <<< "$spec"
  case " $EXISTING " in *" $name "*) continue;; esac
  curl -s "${H[@]}" -X POST http://127.0.0.1:9001/api/listeners \
    -d "{\"name\":\"$name\",\"kind\":\"$kind\",\"addr\":\"$addr\",\"project\":\"default\"}" -o /dev/null || true
done
PUB=$(cat data/keys/plugin.pub 2>/dev/null || echo '')
EXTRA=""
# NB: `EXTRA=$([ -n "$PUB" ] && ...)` would abort under set -e when PUB is empty.
if [ -n "$PUB" ]; then EXTRA=",\"plugin_pubkey\":\"$PUB\""; fi
# WISP_NO_AGENTS=1 keeps the host clean: demo agents belong on the lab VM
# (192.168.32.136), not on the operator workstation.
if [ "${WISP_NO_AGENTS:-0}" = "1" ]; then
  echo "host demo agents disabled (WISP_NO_AGENTS=1)"
else
  printf '{"servers":["http://127.0.0.1:9000"],"psk":"%s","sleep_ms":5000,"jitter_pct":25%s}\n' "$PSK" "$EXTRA" > data/agent-http.json
  printf '{"servers":["tcp://127.0.0.1:9100"],"psk":"%s","sleep_ms":5000,"jitter_pct":25%s}\n' "$PSK" "$EXTRA" > data/agent-tcp.json
  for f in agent-http agent-tcp; do
    ./agent/bin/wisp-agent -config "data/$f.json" > "data-$f.log" 2>&1 &
    sleep 1
  done
fi
sleep 3
N=$(curl -s "${H[@]}" http://127.0.0.1:9001/api/sessions | "$PY" -c 'import sys,json;print(len(json.load(sys.stdin)))')
L=$(curl -s "${H[@]}" http://127.0.0.1:9001/api/listeners | "$PY" -c 'import sys,json;print(len(json.load(sys.stdin)))')
echo "stack up: listeners=$L sessions=$N → http://127.0.0.1:9001/?token=$TOKEN"

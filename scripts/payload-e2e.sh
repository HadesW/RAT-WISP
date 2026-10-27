#!/usr/bin/env bash
# M5 DoD: console -> generate (direct + staged) -> run -> session appears;
# staged token is one-time. Assumes wispd already running on the dev ports.
set -euo pipefail
cd "$(dirname "$0")/.."
TOKEN=$(cat data/api.token); PSK=$(cat data/psk.key)
API="http://127.0.0.1:9001"; AUTH=(-H "X-Wisp-Token: $TOKEN" -H "Content-Type: application/json")
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

sess_count() { curl -s "${AUTH[@]}" "$API/api/sessions" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))'; }

echo "[m5] generate DIRECT darwin payload"
DID=$(curl -s "${AUTH[@]}" -X POST "$API/api/payloads" -d '{"os":"darwin","arch":"arm64","sleep_ms":3000,"jitter_pct":10,"staged":false}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s "${AUTH[@]}" -o "$TMP/direct" "$API/api/payloads/$DID/download"; chmod +x "$TMP/direct"
B0=$(sess_count)
"$TMP/direct" -config "$TMP/none.json" >"$TMP/direct.log" 2>&1 & DPID=$!
trap "kill $DPID 2>/dev/null || true; rm -rf $TMP" EXIT
for i in $(seq 1 20); do [ "$(sess_count)" -gt "$B0" ] && break; sleep 0.5; done
[ "$(sess_count)" -gt "$B0" ] || { echo "[m5] FAIL direct session"; cat "$TMP/direct.log"; exit 1; }
echo "[m5] DIRECT payload ran its own embedded config -> new session ✅"
kill $DPID 2>/dev/null || true

echo "[m5] generate STAGED payload (stager -> one-time stage2)"
SID=$(curl -s "${AUTH[@]}" -X POST "$API/api/payloads" -d '{"os":"darwin","arch":"arm64","sleep_ms":3000,"jitter_pct":10,"staged":true}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s "${AUTH[@]}" -o "$TMP/stager" "$API/api/payloads/$SID/download"; chmod +x "$TMP/stager"
B1=$(sess_count)
"$TMP/stager" >"$TMP/stager.log" 2>&1 & SPID=$!
trap "kill $SPID 2>/dev/null || true; rm -rf $TMP" EXIT
for i in $(seq 1 20); do [ "$(sess_count)" -gt "$B1" ] && break; sleep 0.5; done
[ "$(sess_count)" -gt "$B1" ] || { echo "[m5] FAIL staged session"; cat "$TMP/stager.log"; exit 1; }
echo "[m5] STAGED payload: stager fetched stage2 once -> session ✅"

echo "[m5] replay the SAME stager -> stage2 token must be consumed (no new session)"
kill $SPID 2>/dev/null || true; pkill -9 -f "$TMP/stager" 2>/dev/null || true
B2=$(sess_count)
"$TMP/stager" >"$TMP/stager2.log" 2>&1 || true
sleep 3
[ "$(sess_count)" -le "$B2" ] || { echo "[m5] FAIL: replay produced a session"; exit 1; }
grep -qi 'decrypt failed\|HTTP 404' "$TMP/stager2.log" && echo "[m5] replay rejected (404/decrypt) ✅ one-time token holds"
echo "[m5] PASS ✅ (direct + staged + one-time)"

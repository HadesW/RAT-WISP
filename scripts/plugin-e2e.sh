#!/usr/bin/env bash
# M7 DoD: sign → install → deploy to online agent → exec=5; tamper → refused.
set -euo pipefail
cd "$(dirname "$0")/.."
TOKEN=$(cat data/api.token); PSK=$(cat data/psk.key)
H=(-H "X-Wisp-Token: $TOKEN" -H "Content-Type: application/json")
API=http://127.0.0.1:9001

echo "[p7] keygen + sign demo plugin"
(cd server && go run ./cmd/plugin_sign keygen -dir ../data/keys)
(cd server && go run ./cmd/plugin_sign sign -key ../data/keys/plugin.key \
  -manifest ../scripts/plugins/demo-add.manifest.json -module ../scripts/plugins/demo-add.wasm)

echo "[p7] restart stack (dev-stack) with plugin pubkey wired"
pkill -9 -f 'bin/wisp-agent' 2>/dev/null || true
./scripts/dev-stack.sh >/dev/null
python3 - <<'PY2'
import json
psk = open('data/psk.key').read().strip()
pub = open('data/keys/plugin.pub').read().strip()
cfg = {"servers": ["http://127.0.0.1:9000"], "psk": psk, "sleep_ms": 2000, "plugin_pubkey": pub}
json.dump(cfg, open('data/agent-p7.json', 'w'))
PY2
python3 -c "
import subprocess, time
subprocess.Popen(['agent/bin/wisp-agent','-config','data/agent-p7.json'], stdout=open('data-agent-p7.log','wb'), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)"
sleep 5

echo "[p7] install (signed)"
python3 - <<'PY'
import base64, json, urllib.request
tok = open('data/api.token').read().strip()
man = open('scripts/plugins/demo-add.manifest.json').read()
mod = base64.b64encode(open('scripts/plugins/demo-add.wasm','rb').read()).decode()
sig = base64.b64encode(bytes.fromhex(open('scripts/plugins/demo-add.wasm.sig').read().strip())).decode()
body = json.dumps({"manifest": man, "module_b64": mod, "sig": sig}).encode()
req = urllib.request.Request('http://127.0.0.1:9001/api/plugins', data=body, method='POST', headers={'X-Wisp-Token': tok, 'Content-Type':'application/json'})
print('  install:', urllib.request.urlopen(req).status)
PY

echo "[p7] deploy to online + exec"
python3 - <<'PY'
import json, time, urllib.request
tok = open('data/api.token').read().strip()
def api(path, data=None, method='GET'):
    req = urllib.request.Request('http://127.0.0.1:9001'+path,
        data=json.dumps(data).encode() if data else None, method=method,
        headers={'X-Wisp-Token': tok, 'Content-Type':'application/json'})
    return json.load(urllib.request.urlopen(req))
sess = api('/api/sessions')[0]['id']
api(f'/api/plugins/demo-add/deploy', {"sessions": ["online"]}, 'POST')
time.sleep(4)
r = api('/api/tasks?session='+sess)
load = [t for t in r if t['task']['cmd']==60]
print('  load task:', load[-1]['status'], (load[-1].get('result') or {}).get('output','')[:80])
ex = api('/api/plugins/demo-add/exec', {"session": sess, "entry":"exec", "a":2, "b":3}, 'POST')
time.sleep(4)
r = api('/api/tasks?session='+sess)
t = [x for x in r if x['task']['id']==ex['task']['id']][0]
out = (t.get('result') or {}).get('output','')
print('  exec task:', t['status'], out)
assert '"result":5' in out.replace(' ',''), 'exec result != 5'
print('  ✅ exec(2,3)=5 via WASM plugin')
PY

echo "[p7] tamper: flip one module byte → install must 403"
python3 - <<'PY'
import base64, json, urllib.request, urllib.error
tok = open('data/api.token').read().strip()
man = open('scripts/plugins/demo-add.manifest.json').read()
raw = bytearray(open('scripts/plugins/demo-add.wasm','rb').read())
raw[-3] ^= 0x01  # one byte
sig = base64.b64encode(bytes.fromhex(open('scripts/plugins/demo-add.wasm.sig').read().strip())).decode()
body = json.dumps({"manifest": man, "module_b64": base64.b64encode(bytes(raw)).decode(), "sig": sig}).encode()
req = urllib.request.Request('http://127.0.0.1:9001/api/plugins', data=body, method='POST', headers={'X-Wisp-Token': tok, 'Content-Type':'application/json'})
try:
    urllib.request.urlopen(req)
    raise SystemExit('FAIL: tampered module accepted')
except urllib.error.HTTPError as e:
    print('  refused with', e.code, '✅')
    assert e.code == 403
PY
grep -c 'signature verification FAILED' data-server.log | xargs -I{} echo "[p7] audit lines with bad-signature: {}"
echo "[p7] PASS ✅ (sign→install→deploy→exec→tamper-refused)"

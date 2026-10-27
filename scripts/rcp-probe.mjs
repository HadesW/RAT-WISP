// RCP shell probe: opens the console's WS relay to one agent channel, writes
// commands, prints everything the agent's shell produces. Usage:
//   node scripts/rcp-probe.mjs <agent-id> [kind] [cmds...]
// Env: WISP_API=http://127.0.0.1:9001, token read from data/api.token.
import { readFileSync } from "node:fs";

const api = process.env.WISP_API || "http://127.0.0.1:9001";
const token = readFileSync("data/api.token", "utf8").trim();
const [agent, kind = "shell", ...cmds] = process.argv.slice(2);
if (!agent) {
  console.error("usage: node scripts/rcp-probe.mjs <agent-id> [kind] [cmds...]");
  process.exit(2);
}
const wsBase = api.replace(/^http/, "ws");
const url = `${wsBase}/api/rcp/${agent}/channel?kind=${kind}&token=${encodeURIComponent(token)}`;

const ws = new WebSocket(url);
ws.binaryType = "arraybuffer";
const timeout = setTimeout(() => {
  console.error("[probe] timeout");
  process.exit(1);
}, 20000);

ws.onopen = () => {
  console.error(`[probe] open ${url}`);
  const script = cmds.length ? cmds.join("\r\n") + "\r\n" : "echo rcp-probe-hello\r\n";
  setTimeout(() => ws.send(script), kind === "shell" ? 700 : 300);
  if (kind === "view") setTimeout(() => ws.close(), 4000);
};

let bytes = 0;
let seen = "";
ws.onmessage = (ev) => {
  if (typeof ev.data === "string") {
    process.stdout.write(ev.data);
    return;
  }
  const buf = Buffer.from(ev.data);
  bytes += buf.length;
  process.stdout.write(buf.toString("utf8"));
  if (kind === "shell") {
    seen += buf.toString("utf8");
    // Command echo + command output: two occurrences mean the round-trip
    // actually executed, not just echoed the keystrokes.
    if ((seen.match(/rcp-probe-hello/g) || []).length >= 2) {
      console.error(`\n[probe] matched; ${bytes} bytes total`);
      ws.close();
    }
  }
};

ws.onclose = () => {
  clearTimeout(timeout);
  console.error(`[probe] closed (${bytes} bytes)`);
  process.exit(0);
};
ws.onerror = (e) => {
  console.error("[probe] error", e.message || e);
  process.exit(1);
};
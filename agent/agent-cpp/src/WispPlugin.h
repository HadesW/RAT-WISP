#pragma once

#include "WispConfig.h"
#include "WispJson.h"

// WASM plugin host: Ed25519-verified modules, ABI v0 (exec) and a practical
// ABI v1 subset (alloc/exec_json + gated host_exec). The interpreter covers
// the opcode subset used by the bundled plugins; unsupported opcodes fail the
// plugin call without touching the agent process.

BOOL WispPluginLoad(const WispConfig* cfg, WJVal* args, WJVal* res);
BOOL WispPluginExec(WJVal* args, WJVal* res);
void WispPluginShutdown(void);

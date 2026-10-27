// srdi bootstrap: position-independent shellcode that maps an embedded DLL and
// calls one export. Built with no imports and no CRT, so the image can run from
// any executable buffer.
//
// Shellcode layout produced by server/internal/srdi:
//   [24-byte stub][mapped image][DLL bytes][optional parameter block]
// The stub computes the image base and the .srdicfg pointer, then jumps to
// srdi_entry(image, cfg). All Win32 entry points are resolved by walking the
// PEB, never through the IAT.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "pe_map.hpp"

extern "C" {
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

namespace {

constexpr std::uint32_t mem_commit = 0x1000;
constexpr std::uint32_t mem_reserve = 0x2000;
constexpr std::uint32_t mem_release = 0x8000;
constexpr std::uint32_t page_readwrite = 0x04;

struct unicode_string {
    std::uint16_t length;
    std::uint16_t maximum;
    wchar_t* buffer;
};

struct list_entry {
    list_entry* flink;
    list_entry* blink;
};

// x64 LDR_DATA_TABLE_ENTRY fields reached through InMemoryOrderLinks.
struct ldr_entry {
    list_entry in_load;
    list_entry in_memory;
    list_entry in_init;
    void* dll_base;
    void* entry_point;
    std::uint32_t size_of_image;
    std::uint32_t pad;
    unicode_string full_name;
    unicode_string base_name;
};

struct peb_ldr {
    std::uint32_t length;
    std::uint32_t initialized;
    void* ss_handle;
    list_entry in_load_order;
    list_entry in_memory_order;
};

struct peb {
    std::uint8_t reserved[0x18];
    peb_ldr* ldr;
};

struct srdi_cfg {
    char magic[8];
    std::uint32_t version;
    std::uint32_t image_size;
    std::uint32_t dll_offset;
    std::uint32_t dll_size;
    std::uint32_t params_offset;
    std::uint32_t params_size;
    std::uint32_t flags;
    char export_name[64];
};

constexpr std::uint32_t cfg_version = 1;
constexpr std::uint32_t flag_clear_headers = 1;

// Byte-wise literals keep a second copy of the sentinel out of .rdata: the
// generator requires exactly one SRDICFG occurrence in the mapped image.
bool cfg_ok(const srdi_cfg* c) {
    if (!c || c->version != cfg_version) return false;
    return c->magic[0] == 'S' && c->magic[1] == 'R' && c->magic[2] == 'D' &&
           c->magic[3] == 'I' && c->magic[4] == 'C' && c->magic[5] == 'F' &&
           c->magic[6] == 'G' && c->magic[7] == 1;
}

// Padded so the linked image below stays page-aligned in the mapped PE.
__attribute__((used, section(".srdicfg"), aligned(16)))
volatile srdi_cfg g_cfg = {{'S', 'R', 'D', 'I', 'C', 'F', 'G', 1}, 1, 0, 0, 0, 0, 0, 0, {}};

peb* current_peb() {
    void* p = nullptr;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
    return static_cast<peb*>(p);
}

bool wide_ieq(const wchar_t* s, std::uint16_t bytes, const char* want) {
    const std::uint16_t n = static_cast<std::uint16_t>(bytes / sizeof(wchar_t));
    std::uint16_t i = 0;
    for (; i < n && want[i]; ++i) {
        wchar_t a = s[i];
        if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a + 32);
        char b = want[i];
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + 32);
        if (a != b) return false;
    }
    return i == n || want[i] == 0;
}

std::uint32_t module_size(void* base) {
    peb* p = current_peb();
    if (!p || !p->ldr) return 0;
    list_entry* head = &p->ldr->in_memory_order;
    for (list_entry* it = head->flink; it && it != head; it = it->flink) {
        auto* e = reinterpret_cast<ldr_entry*>(reinterpret_cast<std::uint8_t*>(it) - 0x10);
        if (e->dll_base == base) return e->size_of_image;
    }
    return 0;
}

void* find_module(const char* name) {
    peb* p = current_peb();
    if (!p || !p->ldr) return nullptr;
    list_entry* head = &p->ldr->in_memory_order;
    for (list_entry* it = head->flink; it && it != head; it = it->flink) {
        auto* e = reinterpret_cast<ldr_entry*>(reinterpret_cast<std::uint8_t*>(it) - 0x10);
        if (e->base_name.buffer && wide_ieq(e->base_name.buffer, e->base_name.length, name))
            return e->dll_base;
    }
    return nullptr;
}

// Resolves an export, following "API-SET"/kernelbase forwarder strings.
void* find_export(void* module, std::uint32_t size, const char* name, int depth = 0) {
    using namespace wisp::pe;
    image_info info;
    if (!module || !size || depth > 4 ||
        !parse({static_cast<const std::uint8_t*>(module), static_cast<std::size_t>(size)}, info))
        return nullptr;
    const std::uint32_t export_rva = info.dirs[dir_export][0];
    const std::uint32_t export_size = info.dirs[dir_export][1];
    if (!export_rva || export_size < 40) return nullptr;
    auto* base = static_cast<std::uint8_t*>(module);
    auto* d = base + export_rva;
    const std::uint32_t n_names = detail::rd32(d + 24);
    const std::uint32_t funcs = detail::rd32(d + 28);
    const std::uint32_t names = detail::rd32(d + 32);
    const std::uint32_t ords = detail::rd32(d + 36);
    if (!n_names || names >= size || funcs >= size || ords >= size) return nullptr;
    for (std::uint32_t i = 0; i < n_names; ++i) {
        const std::uint32_t nr = detail::rd32(base + names + i * 4);
        if (nr >= size) return nullptr;
        if (!detail::str_eq(reinterpret_cast<const char*>(base + nr), name)) continue;
        if (static_cast<std::uint64_t>(ords) + (i + 1) * 2 > size) return nullptr;
        const std::uint16_t ord = detail::rd16(base + ords + i * 2);
        if (static_cast<std::uint64_t>(funcs) + (static_cast<std::uint32_t>(ord) + 1) * 4 > size)
            return nullptr;
        const std::uint32_t rva = detail::rd32(base + funcs + static_cast<std::uint32_t>(ord) * 4);
        if (rva < export_rva || rva >= export_rva + export_size) return base + rva;

        // Forwarder: "TARGETDLL.ExportName"; the target usually omits ".dll".
        const char* fwd = reinterpret_cast<const char*>(base + rva);
        std::size_t dot = 0;
        while (fwd[dot] && fwd[dot] != '.') ++dot;
        if (!fwd[dot] || dot >= 60) return nullptr;
        char dll[64];
        for (std::size_t k = 0; k < dot; ++k) dll[k] = fwd[k];
        bool has_suffix = dot >= 4;
        const char* tail = fwd + dot - 4;
        if (has_suffix) {
            for (int k = 0; k < 4; ++k) {
                char c = tail[k];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
                if (c != ".dll"[k]) has_suffix = false;
            }
        }
        std::size_t n = dot;
        if (!has_suffix) {
            dll[n++] = '.';
            dll[n++] = 'd';
            dll[n++] = 'l';
            dll[n++] = 'l';
        }
        dll[n] = 0;
        void* target = find_module(dll);
        if (!target) return nullptr;
        return find_export(target, module_size(target), fwd + dot + 1, depth + 1);
    }
    return nullptr;
}

struct kernel_api {
    void* (*alloc)(void*, std::size_t, std::uint32_t, std::uint32_t) = nullptr;
    bool (*release)(void*, std::size_t, std::uint32_t) = nullptr;
    bool (*protect)(void*, std::size_t, std::uint32_t, std::uint32_t*) = nullptr;
    void* (*load_library)(const char*) = nullptr;
    void* (*get_proc)(void*, const char*) = nullptr;
    bool (*add_function_table)(const void*, std::uint32_t, std::uint64_t) = nullptr;
};

kernel_api g_api;

bool resolve_kernel32() {
    void* k32 = find_module("kernel32.dll");
    if (!k32) return false;
    const std::uint32_t size = module_size(k32);
    auto proc = [&](const char* name) -> void* { return find_export(k32, size, name); };
    g_api.alloc = reinterpret_cast<decltype(g_api.alloc)>(proc("VirtualAlloc"));
    g_api.release = reinterpret_cast<decltype(g_api.release)>(proc("VirtualFree"));
    g_api.protect = reinterpret_cast<decltype(g_api.protect)>(proc("VirtualProtect"));
    g_api.load_library = reinterpret_cast<decltype(g_api.load_library)>(proc("LoadLibraryA"));
    g_api.get_proc = reinterpret_cast<decltype(g_api.get_proc)>(proc("GetProcAddress"));
    g_api.add_function_table =
        reinterpret_cast<decltype(g_api.add_function_table)>(proc("RtlAddFunctionTable"));
    return g_api.alloc && g_api.release && g_api.protect && g_api.load_library && g_api.get_proc;
}

void* boot_alloc(std::uint64_t preferred, std::size_t size) {
    void* p = g_api.alloc(reinterpret_cast<void*>(static_cast<std::uintptr_t>(preferred)), size,
                          mem_reserve | mem_commit, page_readwrite);
    if (!p) p = g_api.alloc(nullptr, size, mem_reserve | mem_commit, page_readwrite);
    return p;
}

bool boot_release(void* base) { return g_api.release(base, 0, mem_release); }

bool boot_protect(void* addr, std::size_t size, std::uint32_t prot, std::uint32_t* old) {
    return g_api.protect(addr, size, prot, old);
}

} // namespace

extern "C" int srdi_entry(void* base, srdi_cfg* cfg);

// The stub passes the image base and cfg pointer. Relocate the image before
// touching any relocated data, then map + enter the embedded DLL.
extern "C" int srdi_entry(void* base, srdi_cfg* cfg) {
    if (!base || !cfg_ok(cfg)) return 1;
    auto* img = static_cast<std::uint8_t*>(base);
    wisp::pe::image_info self;
    const bool parsed = wisp::pe::parse({img, static_cast<std::size_t>(cfg->image_size)}, self);
    if (!parsed) return 2;
    const std::int64_t delta = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(base)) -
                               static_cast<std::int64_t>(self.image_base);
    // The bootstrap is linked RIP-relative and usually has no reloc directory
    // at all; only fail when relocations exist but cannot be applied.
    if (delta != 0 && self.dirs[wisp::pe::dir_basereloc][0] &&
        !wisp::pe::apply_relocations(self, img, delta))
        return 3;
    if (!resolve_kernel32()) return 4;

    const wisp::pe::api api{boot_alloc, boot_release, boot_protect, g_api.load_library,
                            g_api.get_proc, g_api.add_function_table, nullptr, nullptr};
    auto mapped = wisp::pe::map_image({img + cfg->dll_offset, cfg->dll_size}, api);
    if (!mapped) return 5;

    void* params = cfg->params_size ? img + cfg->params_offset : nullptr;
    const char* export_name = cfg->export_name[0] ? cfg->export_name : nullptr;
    auto rc = wisp::pe::run_export(*mapped, api, export_name, "WispStartEx", params,
                                   (cfg->flags & flag_clear_headers) != 0);
    if (!rc) return 6;
    return *rc;
}
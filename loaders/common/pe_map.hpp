// pe_map.hpp — CRT-free PE32+ manual mapper shared by the C++23 loader and the
// sRDI bootstrap. It deliberately depends on nothing but <cstdint>, <cstddef>,
// <span> and <expected>: the sRDI build compiles this header with -nostdlib so
// the resulting image can be run as position-independent shellcode.
//
// The caller supplies the Win32 surface through `api`; the bootstrap resolves
// those pointers from the PEB, the loader from kernel32.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace wisp::pe {

enum class error {
    bad_image,
    no_memory,
    bad_relocs,
    bad_imports,
    cfg_blocked,
};

// Minimal PE64 layout offsets (winnt.h values; keeping them local avoids a
// windows.h dependency in the freestanding build).
inline constexpr std::uint16_t dos_magic = 0x5a4d;
inline constexpr std::uint32_t nt_magic = 0x00004550;
inline constexpr std::uint16_t opt_magic64 = 0x020b;
inline constexpr std::uint16_t file_dll = 0x2000;

inline constexpr std::uint32_t dir_export = 0;
inline constexpr std::uint32_t dir_import = 1;
inline constexpr std::uint32_t dir_exception = 3;
inline constexpr std::uint32_t dir_basereloc = 5;
inline constexpr std::uint32_t dir_tls = 9;
inline constexpr std::uint32_t dir_delay_import = 13;

inline constexpr std::uint32_t scn_mem_execute = 0x20000000;
inline constexpr std::uint32_t scn_mem_write = 0x80000000;

inline constexpr std::uint32_t protect_readonly = 0x02;
inline constexpr std::uint32_t protect_readwrite = 0x04;
inline constexpr std::uint32_t protect_execute = 0x10;
inline constexpr std::uint32_t protect_execute_read = 0x20;
inline constexpr std::uint32_t protect_execute_readwrite = 0x40;

inline constexpr std::uint32_t tls_reason_process_attach = 1;

// Win32 surface required by map_image / run_image. Optional entries stay null
// in the bootstrap when the corresponding capability is not available.
struct api {
    void* (*alloc)(std::uint64_t preferred, std::size_t size) = nullptr;
    bool (*release)(void* base) = nullptr;
    bool (*protect)(void* addr, std::size_t size, std::uint32_t prot, std::uint32_t* old) = nullptr;
    void* (*load_library)(const char* name) = nullptr;
    void* (*get_proc)(void* module, const char* name) = nullptr;
    bool (*add_function_table)(const void* table, std::uint32_t count, std::uint64_t base) = nullptr;
    bool (*cfg_enabled)() = nullptr;
    bool (*valid_target)(void* addr) = nullptr;
};

struct section_info {
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t raw_size;
    std::uint32_t raw_ptr;
    std::uint32_t characteristics;
};

struct image_info {
    const std::uint8_t* raw = nullptr;
    std::uint32_t raw_size = 0;
    std::uint32_t nt_off = 0;
    std::uint32_t sec_off = 0;
    std::uint16_t nsec = 0;
    std::uint16_t dll_chars = 0;
    std::uint32_t size_image = 0;
    std::uint32_t size_headers = 0;
    std::uint32_t entry = 0;
    std::uint64_t image_base = 0;
    std::uint32_t dirs[16][2] = {};
};

struct mapped_image {
    std::uint8_t* base = nullptr;
    std::uint32_t size = 0;
    std::uint32_t entry = 0;
    std::uint32_t headers = 0;
    std::uint32_t export_rva = 0;
    std::uint32_t export_size = 0;
    std::uint32_t tls_rva = 0;
    std::uint32_t tls_size = 0;
    std::uint64_t image_base = 0;
    bool cfg_image = false;
};

namespace detail {

inline std::uint16_t rd16(const void* p) {
    std::uint16_t v;
    __builtin_memcpy(&v, p, sizeof v);
    return v;
}

inline std::uint32_t rd32(const void* p) {
    std::uint32_t v;
    __builtin_memcpy(&v, p, sizeof v);
    return v;
}

inline std::uint64_t rd64(const void* p) {
    std::uint64_t v;
    __builtin_memcpy(&v, p, sizeof v);
    return v;
}

inline void wr32(void* p, std::uint32_t v) { __builtin_memcpy(p, &v, sizeof v); }
inline void wr64(void* p, std::uint64_t v) { __builtin_memcpy(p, &v, sizeof v); }

inline void copy(uint8_t* dst, const uint8_t* src, std::size_t n) {
    while (n--) *dst++ = *src++;
}

inline void zero(uint8_t* dst, std::size_t n) {
    while (n--) *dst++ = 0;
}

inline bool str_eq(const char* a, const char* b) {
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

inline bool dir_ok(const image_info& img, std::uint32_t idx) {
    const std::uint32_t rva = img.dirs[idx][0];
    const std::uint32_t size = img.dirs[idx][1];
    if (!rva || !size) return false;
    return static_cast<std::uint64_t>(rva) + size <= img.size_image;
}

} // namespace detail

// Parses and validates enough of the PE to know every copy is in bounds.
inline bool parse(std::span<const std::uint8_t> src, image_info& out) {
    using namespace detail;
    out = {};
    out.raw = src.data();
    out.raw_size = static_cast<std::uint32_t>(src.size());
    if (src.size() < 0x40 || rd16(src.data()) != dos_magic) return false;
    const std::uint32_t e = rd32(src.data() + 0x3c);
    if (e < 0x40 || static_cast<std::uint64_t>(e) + 4 + 20 > src.size()) return false;
    if (rd32(src.data() + e) != nt_magic) return false;
    const std::uint8_t* fh = src.data() + e + 4;
    const std::uint16_t opt_size = rd16(fh + 16);
    if (opt_size < 112 || static_cast<std::uint64_t>(e) + 24 + opt_size > src.size()) return false;
    const std::uint8_t* opt = fh + 20;
    if (rd16(opt) != opt_magic64) return false;
    const std::uint32_t size_image = rd32(opt + 56);
    const std::uint32_t size_headers = rd32(opt + 60);
    if (size_image == 0 || size_image > (256u << 20) || size_headers == 0 ||
        size_headers > src.size() || size_headers > size_image)
        return false;
    const std::uint32_t nsec = rd16(fh + 2);
    const std::uint32_t sec_off = e + 24 + opt_size;
    if (nsec == 0 || nsec > 96 ||
        static_cast<std::uint64_t>(sec_off) + static_cast<std::uint64_t>(nsec) * 40 > src.size())
        return false;
    for (std::uint32_t i = 0; i < nsec; ++i) {
        const std::uint8_t* s = src.data() + sec_off + i * 40;
        const std::uint32_t virt = rd32(s + 8) ? rd32(s + 8) : rd32(s + 16);
        const std::uint32_t raw_size = rd32(s + 16);
        const std::uint32_t raw_ptr = rd32(s + 20);
        if (raw_size && (static_cast<std::uint64_t>(raw_ptr) + raw_size > src.size() ||
                         static_cast<std::uint64_t>(rd32(s + 12)) + virt > size_image))
            return false;
    }
    out.nt_off = e;
    out.sec_off = sec_off;
    out.nsec = static_cast<std::uint16_t>(nsec);
    out.dll_chars = rd16(opt + 70);
    out.size_image = size_image;
    out.size_headers = size_headers;
    out.entry = rd32(opt + 16);
    out.image_base = rd64(opt + 24);
    const std::uint32_t n_dirs = rd32(opt + 108);
    for (std::uint32_t i = 0; i < 16 && i < n_dirs; ++i) {
        out.dirs[i][0] = rd32(opt + 112 + i * 8);
        out.dirs[i][1] = rd32(opt + 112 + i * 8 + 4);
    }
    return true;
}

inline bool is_dll(std::span<const std::uint8_t> src) {
    image_info img;
    return parse(src, img) && (detail::rd16(img.raw + img.nt_off + 4 + 18) & file_dll);
}

inline section_info section_at(const image_info& img, std::uint32_t i) {
    const std::uint8_t* s = img.raw + img.sec_off + i * 40;
    return section_info{detail::rd32(s + 8), detail::rd32(s + 12), detail::rd32(s + 16),
                        detail::rd32(s + 20), detail::rd32(s + 36)};
}

inline bool apply_relocations(const image_info& img, std::uint8_t* base, std::int64_t delta) {
    using namespace detail;
    if (!dir_ok(img, dir_basereloc)) return false;
    const std::uint32_t rva = img.dirs[dir_basereloc][0];
    const std::uint32_t sz = img.dirs[dir_basereloc][1];
    for (std::uint32_t at = 0; at + 8 <= sz;) {
        const std::uint32_t page = rd32(base + rva + at);
        const std::uint32_t block = rd32(base + rva + at + 4);
        if (block < 8 || at + block > sz) return false;
        for (std::uint32_t o = 8; o + 2 <= block; o += 2) {
            const std::uint16_t e = rd16(base + rva + at + o);
            const std::uint16_t kind = e >> 12;
            const std::uint32_t off = e & 0x0fff;
            if (kind == 0) continue; // IMAGE_REL_BASED_ABSOLUTE
            if (static_cast<std::uint64_t>(page) + off + 8 > img.size_image) return false;
            std::uint8_t* slot = base + page + off;
            if (kind == 10) { // IMAGE_REL_BASED_DIR64
                wr64(slot, rd64(slot) + static_cast<std::uint64_t>(delta));
            } else if (kind == 3) { // IMAGE_REL_BASED_HIGHLOW
                wr32(slot, static_cast<std::uint32_t>(static_cast<std::int64_t>(rd32(slot)) + delta));
            } else {
                return false;
            }
        }
        at += block;
    }
    return true;
}

// Resolves one thunk array (import or delay-import) into `iat`.
inline bool bind_thunks(const api& a, std::uint8_t* base, std::uint32_t image_size, void* module,
                        std::uint32_t name_rva, std::uint32_t iat_rva) {
    using namespace detail;
    if (!name_rva || name_rva >= image_size || iat_rva >= image_size) return false;
    std::uint8_t* names = base + name_rva;
    std::uint8_t* iat = base + iat_rva;
    for (;;) {
        if (static_cast<std::uint64_t>(names - base) + 8 > image_size ||
            static_cast<std::uint64_t>(iat - base) + 8 > image_size)
            return false;
        const std::uint64_t thunk = rd64(names);
        if (!thunk) return true;
        void* proc;
        if (thunk & (1ull << 63)) {
            proc = a.get_proc(module, reinterpret_cast<const char*>(static_cast<std::uintptr_t>(thunk & 0xffff)));
        } else {
            const std::uint32_t rva = static_cast<std::uint32_t>(thunk);
            if (rva + 3 > image_size) return false;
            proc = a.get_proc(module, reinterpret_cast<const char*>(base + rva + 2));
        }
        if (!proc) return false;
        wr64(iat, static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(proc)));
        names += 8;
        iat += 8;
    }
}

inline bool resolve_imports(const image_info& img, const api& a, std::uint8_t* base) {
    using namespace detail;
    if (!img.dirs[dir_import][0] || !img.dirs[dir_import][1]) return true;
    if (!dir_ok(img, dir_import)) return false;
    const std::uint32_t rva = img.dirs[dir_import][0];
    const std::uint32_t sz = img.dirs[dir_import][1];
    for (std::uint32_t i = 0; i + 20 <= sz; i += 20) {
        const std::uint8_t* de = base + rva + i;
        const std::uint32_t oft = rd32(de);
        const std::uint32_t name_rva = rd32(de + 12);
        const std::uint32_t first = rd32(de + 16);
        if (!oft && !name_rva && !first) return true;
        if (!name_rva || name_rva >= img.size_image || first >= img.size_image ||
            (oft && oft >= img.size_image))
            return false;
        void* mod = a.load_library(reinterpret_cast<const char*>(base + name_rva));
        if (!mod) return false;
        if (!bind_thunks(a, base, img.size_image, mod, oft ? oft : first, first)) return false;
    }
    return false;
}

// Delay-load descriptors are 32 bytes. Attribute bit 0 selects RVA fields;
// the legacy form stores VAs and needs the image base subtracted.
inline bool resolve_delay_imports(const image_info& img, const api& a, std::uint8_t* base) {
    using namespace detail;
    if (!img.dirs[dir_delay_import][0] || !img.dirs[dir_delay_import][1]) return true;
    if (!dir_ok(img, dir_delay_import)) return false;
    const std::uint32_t rva = img.dirs[dir_delay_import][0];
    const std::uint32_t sz = img.dirs[dir_delay_import][1];
    const auto as_rva = [&](std::uint32_t v) -> std::uint32_t {
        return v < img.size_image ? v : static_cast<std::uint32_t>(v - img.image_base);
    };
    for (std::uint32_t i = 0; i + 32 <= sz; i += 32) {
        const std::uint8_t* de = base + rva + i;
        const std::uint32_t attrs = rd32(de);
        const std::uint32_t name_rva = as_rva(rd32(de + 4));
        const std::uint32_t iat = as_rva(rd32(de + 12));
        const std::uint32_t names = as_rva(rd32(de + 16));
        if (!name_rva && !iat && !names) return true;
        (void)attrs;
        if (!name_rva || name_rva >= img.size_image || iat >= img.size_image || names >= img.size_image)
            return false;
        void* mod = a.load_library(reinterpret_cast<const char*>(base + name_rva));
        if (!mod) return false;
        if (!bind_thunks(a, base, img.size_image, mod, names, iat)) return false;
    }
    return false;
}

inline void register_unwind(const image_info& img, const api& a, std::uint8_t* base) {
    using namespace detail;
    if (!dir_ok(img, dir_exception) || !a.add_function_table) return;
    a.add_function_table(base + img.dirs[dir_exception][0], img.dirs[dir_exception][1] / 12,
                         static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(base)));
}

inline void protect_sections(const image_info& img, const api& a, std::uint8_t* base) {
    for (std::uint32_t i = 0; i < img.nsec; ++i) {
        const section_info s = section_at(img, i);
        if (!s.virtual_size) continue;
        std::uint32_t prot;
        if (s.characteristics & scn_mem_write)
            prot = (s.characteristics & scn_mem_execute) ? protect_execute_readwrite : protect_readwrite;
        else
            prot = (s.characteristics & scn_mem_execute) ? protect_execute_read : protect_readonly;
        std::uint32_t old = 0;
        a.protect(base + s.virtual_address, s.virtual_size, prot, &old);
    }
}

// Maps the image into this process and performs every fixup the OS loader
// would: sections, relocations, imports, delay imports, unwind table, section
// permissions and CFG call-target hints.
inline std::expected<mapped_image, error> map_image(std::span<const std::uint8_t> src, const api& a) {
    using namespace detail;
    image_info img;
    mapped_image out;
    if (!parse(src, img) || !a.alloc || !a.protect || !a.load_library || !a.get_proc)
        return std::unexpected(error::bad_image);
    if (a.cfg_enabled && a.cfg_enabled()) {
        // A policy that bans dynamic code or requires signed images cannot host
        // a hand-mapped image; fail before touching memory.
        if (!a.valid_target) return std::unexpected(error::cfg_blocked);
    }
    std::uint8_t* base = static_cast<std::uint8_t*>(a.alloc(img.image_base, img.size_image));
    if (!base) return std::unexpected(error::no_memory);
    out.base = base;

    copy(base, img.raw, img.size_headers);
    for (std::uint32_t i = 0; i < img.nsec; ++i) {
        const section_info s = section_at(img, i);
        if (!s.raw_size) continue;
        const std::uint32_t virt = s.virtual_size ? s.virtual_size : s.raw_size;
        const std::uint32_t n = s.raw_size < virt ? s.raw_size : virt;
        copy(base + s.virtual_address, img.raw + s.raw_ptr, n);
    }

    const std::int64_t delta = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(base)) -
                               static_cast<std::int64_t>(img.image_base);
    if (delta != 0 && !apply_relocations(img, base, delta)) {
        if (a.release) a.release(base);
        return std::unexpected(error::bad_relocs);
    }
    if (!resolve_imports(img, a, base) || !resolve_delay_imports(img, a, base)) {
        if (a.release) a.release(base);
        return std::unexpected(error::bad_imports);
    }
    register_unwind(img, a, base);
    protect_sections(img, a, base);

    out.size = img.size_image;
    out.entry = img.entry;
    out.headers = img.size_headers;
    out.export_rva = img.dirs[dir_export][0];
    out.export_size = img.dirs[dir_export][1];
    out.tls_rva = img.dirs[dir_tls][0];
    out.tls_size = img.dirs[dir_tls][1];
    out.image_base = img.image_base;
    out.cfg_image = (img.dll_chars & 0x4000) != 0;
    return out;
}

inline void valid_target(const mapped_image& img, const api& a, void* target) {
    (void)img;
    if (a.cfg_enabled && a.cfg_enabled() && a.valid_target && target) a.valid_target(target);
}

inline void call_entry(const mapped_image& img, const api& a) {
    if (!img.entry) return;
    using entry_fn = std::uint32_t (*)(void*, std::uint32_t, void*);
    auto fn = reinterpret_cast<entry_fn>(img.base + img.entry);
    valid_target(img, a, reinterpret_cast<void*>(fn));
    fn(img.base, tls_reason_process_attach, nullptr);
}

// The OS never fires TLS callbacks for a manual-mapped image; replay them.
inline void notify_tls(const mapped_image& img, const api& a, std::uint32_t reason) {
    using namespace detail;
    if (img.tls_size < 40) return;
    std::uint8_t* t = img.base + img.tls_rva;
    const std::uint64_t lo = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(img.base));
    const std::uint64_t hi = lo + img.size;
    const std::int64_t delta = static_cast<std::int64_t>(lo) - static_cast<std::int64_t>(img.image_base);
    std::uint64_t linked = rd64(t + 24);
    if (!linked) return;
    if (linked < lo || linked >= hi) linked = static_cast<std::uint64_t>(static_cast<std::int64_t>(linked) + delta);
    if (linked < lo || linked >= hi) return;
    auto* list = reinterpret_cast<std::uint64_t*>(static_cast<std::uintptr_t>(linked));
    for (std::uint32_t i = 0; i < 64; ++i) {
        std::uint64_t cb = list[i];
        if (!cb) break;
        if (cb < lo || cb >= hi) cb = static_cast<std::uint64_t>(static_cast<std::int64_t>(cb) + delta);
        if (cb < lo || cb >= hi) break;
        using tls_fn = void (*)(void*, std::uint32_t, void*);
        auto fn = reinterpret_cast<tls_fn>(static_cast<std::uintptr_t>(cb));
        valid_target(img, a, reinterpret_cast<void*>(fn));
        fn(img.base, reason, nullptr);
    }
}

inline void* resolve_export(const mapped_image& img, const char* want) {
    using namespace detail;
    if (!img.export_rva || img.export_size < 40) return nullptr;
    std::uint8_t* d = img.base + img.export_rva;
    const std::uint32_t n_names = rd32(d + 24);
    const std::uint32_t funcs = rd32(d + 28);
    const std::uint32_t names = rd32(d + 32);
    const std::uint32_t ords = rd32(d + 36);
    if (!n_names || names >= img.size || funcs >= img.size || ords >= img.size) return nullptr;
    for (std::uint32_t i = 0; i < n_names; ++i) {
        const std::uint32_t nr = rd32(img.base + names + i * 4);
        if (nr >= img.size) return nullptr;
        if (!str_eq(reinterpret_cast<const char*>(img.base + nr), want)) continue;
        if (static_cast<std::uint64_t>(ords) + (i + 1) * 2 > img.size) return nullptr;
        const std::uint16_t ord = rd16(img.base + ords + i * 2);
        if (static_cast<std::uint64_t>(funcs) + (static_cast<std::uint32_t>(ord) + 1) * 4 > img.size)
            return nullptr;
        const std::uint32_t rva = rd32(img.base + funcs + static_cast<std::uint32_t>(ord) * 4);
        if (rva >= img.export_rva && rva < img.export_rva + img.export_size) return nullptr;
        return img.base + rva;
    }
    return nullptr;
}

inline void wipe_headers(const mapped_image& img, const api& a) {
    detail::zero(img.base, img.headers);
    std::uint32_t old = 0;
    a.protect(img.base, 0x1000, protect_readonly, &old);
}

// Entry + TLS + export, the common sequence used by both the loader and the
// sRDI bootstrap. Returns the export's value; the bool says whether a call
// target was found.
inline std::expected<int, error> run_export(mapped_image& img, const api& a, const char* export_name,
                                            const char* fallback, void* params, bool wipe) {
    call_entry(img, a);
    notify_tls(img, a, tls_reason_process_attach);
    void* start = export_name ? resolve_export(img, export_name) : nullptr;
    if (!start && fallback) start = resolve_export(img, fallback);
    if (!start) return std::unexpected(error::bad_image);
    valid_target(img, a, start);
    if (wipe) wipe_headers(img, a);
    using export_fn = int (*)(void*, void*, char*, int);
    auto fn = reinterpret_cast<export_fn>(start);
    return fn(params, img.base, nullptr, 0);
}

} // namespace wisp::pe

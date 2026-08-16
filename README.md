# RAT-WISP

Wisp 是一个跨平台 C2 管理控制台（也可作为远程管理工具Remote Administration Tool使用），基于 Go + Wails v3 + React + TypeScript 构建。支持多协议监听、Agent 远程管理、远程桌面、文件管理等功能。

## 文档

- [English README](docs/README_EN.md)
- [协议架构（4 类协议 / 传输矩阵 / 安全模型）](docs/PROTOCOL_ARCH.md)
- [Agent 部署与执行流程](docs/AGENT_DEPLOYMENT.md)（直接运行 / sRDI / stager / bypass 时机）
- [Malleable 流量伪装](docs/MALLEABLE.md)
- [脚本 Hook 框架](docs/HOOKS.md)（lua pre/post hook、流量整形、任务改写、输出脱敏）
- [部署说明](docs/DEPLOY.md)
- [插件平台规划](docs/PLUGIN_PLATFORM_PLAN.md)

## 截图

![主面板](pic/2026-08-09_001034.png)

![远程控制1](pic/2026-08-09_002723.png)

![远程控制2](pic/2026-08-09_003817.png)

![文件管理](pic/2026-08-09_004432.png)

![截屏](pic/2026-08-09_004840.png)

## 主要功能

- 多协议监听器（TCP / HTTP / HTTPS / KCP / QUIC）
- 远程 Shell 与交互式 Shell
- 远程桌面（RDP）+ 独立 RCP 低延迟通道（TCP / KCP）
- 文件管理（浏览、上传、下载，分块断点聚合）
- Payload 一键生成（agent exe/dll、sRDI shellcode、C/Go stager、DLL stager）
- Malleable 流量伪装（自定义 URI / UA 轮换 / stage 前缀）
- Lua / WASM Hook 脚本引擎（流量整形、任务改写、输出脱敏）
- PSK 认证、TLS 证书固定
- RSA + AES-256-CTR + HMAC 混合加密通信

## 技术栈

### 控制端（Server / GUI）

| 层级 | 技术 |
|------|------|
| 桌面框架 | Wails v3（Go + WebView2 / WebKitGTK） |
| 后端 | Go 1.25 |
| 前端 | React 19 + TypeScript + Vite |
| 状态管理 | Zustand |
| 数据库 | SQLite3（`github.com/mattn/go-sqlite3`） |
| 低延迟传输 | KCP（`xtaci/kcp-go/v5`）、QUIC（`quic-go`） |
| 脚本引擎 | gopher-lua（Hook 脚本）、wazero（WASM 插件） |
| WebSocket | coder/websocket（前端实时推送） |

### Agent（Go / Rust 双实现）

| 语言 | 用途 |
|------|------|
| Go | 完整 agent（模板覆盖生成，多平台） |
| **Rust** | **新一代 agent**（`agent-rust/`，编译为 DLL 反射加载 + 独立 EXE） |

Rust agent 依赖：`aes`/`ctr`/`hmac`/`sha2`（Go 互操作加解密）、`rsa`（OAEP-SHA256）、`ureq`（HTTP/HTTPS）、`kcp`（可靠 UDP）、`quinn`+`tokio`+`rustls`（QUIC/TLS1.3）、`serde`、`windows-sys`（Win32 API）。

## 核心协议与架构

详见 [docs/PROTOCOL_ARCH.md](docs/PROTOCOL_ARCH.md) —— 项目采用 **4 类协议架构**：

| 类型 | 用途 | 实现状态 |
|------|------|----------|
| **Type 1 主通讯** | 命令/心跳/结果轮询；HTTP / HTTPS / TCP / KCP / QUIC | ✅ 全传输 |
| **Type 2 RCP 长连接** | 远程桌面低延迟通道（独立于轮询休眠），TCP / KCP | ✅ |
| **Type 3 文件传输** | 分块上传/下载（512KB chunk，服务端聚合） | ✅ |
| **Type 4 Stage 下载** | 同一步进端点 + 不同 handler 分发（raw XOR / JSON AES） | ✅ |

### 安全模型
- **混合加密**：RSA-OAEP（SHA-256）握手交换会话密钥 → AES-256-CTR + HMAC-SHA256（IV+密文+MAC，与 Go 双端互操作）
- **PSK 认证**：注册携带预共享密钥校验
- **TLS**：HTTPS/QUIC 自签证书 + 客户端跳过验证（会话层已加密，传输层做混淆）

### Payload / 免杀技术
- **sRDI 反射加载**（`internal/srdi`）：Go/Rust DLL 打包为位置无关 shellcode，内存执行，无磁盘落盘
- **多态编码**（`internal/poly`）：SGN 风格自解码，每次构建产物唯一
- **极简 C Stager**（`native/stager_stub.c`）：CS 风格 ~2.3KB 首段，PEB-walk 手解析 winsock，HTTP 拉取 stage2 后 XOR 解密跳转
- **Stager 模板化**：EXE/DLL 预编译模板 + config 二进制 patch（哨兵定位覆写），生成时**无需 mingw 编译器**
- **Malleable 流量伪装**：自定义 URI / UA 轮换 / stage 前缀（[docs/MALLEABLE.md](docs/MALLEABLE.md)）

### 扩展框架
- **Lua / WASM Hook**：pre/post hook 观察与改写流量、任务、输出脱敏（[docs/HOOKS.md](docs/HOOKS.md)）
- **插件注册表**：Rust agent 按 feature 裁剪插件（shell / file / rdp / keylog / persist / evasion…）

## 快速开始

**环境要求**：Go 1.25+、Node.js 18+

```bash
cd src

# 安装依赖并构建前端
cd frontend && npm install && npm run build && cd ..
go mod tidy

# 开发模式
wails3 dev

# 构建（Linux/macOS 用 make，Windows 用 build.bat）
make build-app          # 或 build.bat server
make agent              # 或 build.bat agent
make agent-all          # 或 build.bat agent-all
make release            # 或 build.bat release —— 把 loaders/native/scripts 资源归入 bin\

# 运行
./bin/wisp              # macOS/Linux
bin\wisp.exe            # Windows 可直接双击
```

## 发布目录结构（bin\）

| 路径 | 内容 |
|------|------|
| `bin/wisp(.exe)` | 服务端（Wails GUI，含 shellcode/stager/脚本/运营服务） |
| `bin/templates/` | 6 平台 agent 模板 + 2 个 DLL 模板 + **C stager EXE/DLL 预编译模板** + **Rust stager 模板**（`build.bat templates` 重新生成） |
| `bin/payloads/` | 生成的 payload：shellcode（sRDI 各格式）、stager、agent exe/dll |
| `bin/loaders/` | 用户 loader 模板（C / Rust / Go / PowerShell / VBA） |
| `bin/native/` | sRDI 反射加载器 + **纯 C 极简 stager** C 源码 + 重建脚本（`build_srdi.sh` / `build_stager.sh`） |
| `bin/scripts/` | gopher-lua 脚本引擎脚本目录 |
| `bin/reports/` | MITRE 报告导出目录 |
| `bin/data/` | SQLite 数据库 + RSA 密钥 + TLS 证书（运行时生成） |

> Shellcode 能力是**按需生成**的：在 Payload 对话框选「Shellcode(sRDI)」或「分阶段(Staged)」，
> 服务端从 `bin/templates/agent_windows_amd64.dll` 用 sRDI 打包成 shellcode 输出到 `bin/payloads/`。
> 所以模板（templates/）是源头，shellcode 是运行时产物。
>
> **Stager 三种实现**（Payload → 分阶段 → Stager 实现）：
> - `Go`（默认）：完整 Go 运行时，支持 HTTPS，产物数十 KB（EXE）
> - `C 极简`：CS 风格首段，约 2.3 KB 位置无关 shellcode（raw/b64/c/c#/ps1/py/vba/hta 任意格式），
>   仅 HTTP；stager 自行 PEB-walk 解析 winsock、GET `/stage/<token>?raw=1`、XOR 解密后跳转。
>   源码在 `bin/native/stager_stub.c`，配置（ip/port/key/path）由 `internal/stager.Build` 打补丁。
> - `Rust`：预编译模板 + config 二进制 patch（`internal/stager.PatchRustStager`），零编译；
>   **HTTP/HTTPS 均支持**（WinINet，自签跳过），AES-GCM JSON 协议（同 Go stager），
>   GET stage → 解密 → VirtualAlloc 执行。产物 `bin/templates/stager_rust_template.exe`
>   （约 272 KB，`stager-rust/` 源码）。
>
> **C Stager 模板化**（v2026-08）：`bin/templates/stager_c_template.exe`（17 KB）与
> `stager_c_template.dll`（14 KB，导出 `StartStager`，DllMain 自动触发）为预编译模板，
> 生成时用 `internal/stager.PatchTemplateBlob` 二进制 patch 哨兵 config 区（IP/port/key/path），
> **部署/生成无需 mingw 编译器**；模板由 `cmd/gen_stager_templates` 一次性构建。

## 免责声明

本工具仅供安全研究和授权测试使用。

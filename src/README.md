# Wisp — 桌面 C2 管理与控制框架

Wisp 是一个基于 [Wails v3](https://wails.io/) 的跨平台桌面 C2（命令与控制）管理控制台。它以 Go 编写的服务端 + Wails WebView 前端（React + TypeScript）构成单进程 GUI，内置加密 C2 通讯、实时远程控制与静态文件分发三类独立协议通道，并提供免依赖的模板化 payload 生成能力。

> ⚠️ **用途声明**：本项目仅用于授权环境下的安全测试、渗透演练与红队研究。请勿用于未授权的系统。使用者须对自身行为负责。

---

## 功能特性

- **多协议监听器**：TCP / HTTP / HTTPS / **KCP（UDP）** 四种监听协议，可配置 PSK 预共享密钥；Host（回连地址）/ Bind（监听地址）分离，兼容 Cobalt Strike 用法；KCP 为低延迟可靠传输，规避 TCP 慢启动，链路抖动时 checkin 更敏捷
- **会话管理**：上线注册、sleep+jitter 心跳轮询、死亡检测、会话删除与备注
- **命令执行**：`shell / ls / cd / cat / pwd / ps / kill / sysinfo / sleep / exit`
- **文件管理**：目录列表、新建 / 重命名 / 删除、文件上传 / 下载（分块聚合、超时清理）、远程执行
- **交互式 shell**：持久子进程的 stdin/stdout 循环，支持编码转换
- **远程桌面**：JPEG 帧流实时预览 + 鼠标 / 键盘注入
- **远程控制（RCP）**：独立长连接（**TCP 或 KCP/UDP 可选**），20 FPS 不受 sleep 影响，RSA challenge + 会话密钥双向认证，逐包 AES 加密
- **截图**：单帧抓取并保存到服务端 `data/screenshots/`
- **文件服务器**：HTTP(S) 静态分发，用于托管 agent / payload 供目标机下载，状态持久化、重启自动恢复
- **Payload 生成**：6 平台（windows / linux / darwin × amd64 / arm64），模板化 overlay 与源码编译双方案
- **安全通讯**：RSA-2048 密钥交换 + AES-256-CTR + HMAC-SHA256 会话密钥，证书指纹固定
- **持久化**：SQLite（WAL）+ 敏感字段 AES-GCM 加密存储
- **i18n**：中文 / English 界面切换

---

## 架构总览

通讯体系由三类**彼此隔离**的协议组成（详见 [`docs/PROTOCOL-ARCHITECTURE.md`](docs/PROTOCOL-ARCHITECTURE.md)）：

| 类 | 协议 | 用途 | 传输 | 加密 | 实时性 |
|----|------|------|------|------|--------|
| 第一类 | C2 轮询 | 注册 / checkin / 任务下发 / 结果回传 / shell / 文件 | TCP / KCP(UDP) 自定义二进制 或 HTTP 轮询 | RSA 换发 + AES-CTR + HMAC 会话密钥 | 低（受 sleep/jitter 控制） |
| 第二类 | RCP 远程控制 | 实时屏幕流 + 鼠标 / 键盘注入 | 独立 TCP / KCP(UDP) 长连接（自动端口，窗口内可切换） | RSA challenge + 会话密钥逐包 AES | 高（20 FPS） |
| 第三类 | 文件服务 | 静态分发 agent / payload | 独立 HTTP(S) | HTTPS 自签证书 | 无状态 |

三类协议端口、协议栈、状态完全隔离，停止任一服务不影响其余两类。

---

## 目录结构

```
wisp/
├── main.go               # 服务端入口（Wails 应用装配）
├── wails.json / go.mod   # Wails & Go 模块配置
├── build.bat / build.sh  # Windows / Unix 构建脚本
├── Makefile / Taskfile.yml
├── bin/                  # 构建产物
│   ├── wisp.exe          # 服务端 + GUI
│   ├── agent.exe         # 当前平台 agent
│   ├── templates/        # 6 平台 agent 模板（模板化 payload 依赖，需与 wisp.exe 同目录分发）
│   └── data/             # 运行数据（自动生成）
├── frontend/             # React 19 + TS + Vite + zustand + @wailsio/runtime
│   └── src/
│       ├── components/   # 会话表 / 控制台 / 监听器 / 文件管理 / 远程桌面 / RCP / Payload 等
│       ├── stores/       # zustand 状态
│       └── i18n/         # 中英文文案
├── internal/
│   ├── db/               # SQLite 持久化 + 字段加密 + 迁移
│   └── server/           # C2 核心：监听器、注册、checkin、任务调度、RCP、TLS
├── services/             # Wails 服务层（Listener / Session / Payload / FileServer / Screenshot）
├── shared/protocol/      # 协议常量、封包、加解密
├── agent/                # 独立 Go 模块（CGO 可选），支持 CLI / DLL 双形态
├── cmd/                  # e2e / healthcheck / loadcheck 辅助工具
└── docs/                 # 架构与规划文档
```

---

## 环境要求

- **Go** 1.25+（构建服务端与 agent）
- **Node.js** 20+（构建前端）
- **gcc**（MinGW-w64，Windows 下 go-sqlite3 依赖 CGO）；也可 `winget install BrechtSanders.WinLibs.POSIX.UCRT` 自动发现
- 构建 agent 无需 cgo（`CGO_ENABLED=0`），但 **DLL 形态**的 agent 需要 gcc（c-shared）

---

## 构建

Windows（`build.bat`）：

```bat
build.bat all          :: 前端 + 6 平台模板 + wisp.exe + agent.exe（默认）
build.bat frontend     :: 仅前端
build.bat templates    :: 生成 6 平台模板到 bin\templates\
build.bat server       :: 前端 + wisp.exe
build.bat agent        :: 当前平台 agent
build.bat agent-all    :: 交叉编译 6 平台 agent
build.bat clean        :: 清理 bin\ 与 frontend\dist\
```

Unix / macOS（`build.sh` 或 `make`）：

```bash
./build.sh all          # 前端 + wisp + agent
./build.sh server
./build.sh agent-all
make all                # 等价前端 + wisp
```

> 模板（`bin/templates/`）不再内嵌进 wisp.exe：生成模板化 payload 时，服务端会从 **wisp.exe 同目录的 `templates/`** 读取对应平台的预编译 agent。

---

## 快速上手

1. **启动服务端**：运行 `bin/wisp.exe`（开发模式可 `go run .`），或拷贝 `wisp.exe` + `templates/` 到目标服务器机器。
2. **创建监听器**：`Listeners` 页 → 新建。设置名称、协议（TCP/HTTP/HTTPS/KCP）、**回连地址 Host**（留空自动检测本机局域网 IP，这是 agent 实际连接地址）、监听地址 Bind（默认 `0.0.0.0`）、端口，可选 PSK；保存后启动。KCP 监听器走 UDP，同一端口可作为 KCP 通道。
3. **生成 Payload**：`Payload` 对话框选择监听器、目标平台与架构、生成方式（模板化默认 / 源码编译），生成后得到 agent 二进制（transport 自动跟随监听器协议）。
4. **部署上线**：将 payload 拷贝到目标机运行，控制台出现新会话（`[Server] New session`）。
5. **交互控制**：右键会话执行命令、打开 shell / 文件管理 / 远程桌面 / 远程控制 / 截图；`File Server` 页可挂载目录分发文件。

### 回连地址（Host）说明

监听器采用 CS 风格 **Host / Bind 分离**：`Host` 是写入 payload 的回连地址，`Bind` 是服务端本机绑定的地址。若 `Host` 留空则自动检测本机局域网 IP——把 wisp.exe 部署在 `192.168.75.130` 时，生成的 payload 会自动回连该 IP，而不是连本机 `127.0.0.1`。

---

## Payload 生成

- **模板化（默认）**：从 wisp.exe 旁的 `templates/` 读取预编译 agent，在文件尾部追加 `overlay`（`OverlayMarker + base64 JSON 配置`）；agent 启动时自行从自身 EXE 末尾解析配置。无需 Go 工具链 / 源码，生成速度最快。
- **源码编译**：从 **wisp.exe 同目录的 `agent-src/`**（即本仓库 `agent/`）实时 `go build`，配置经 `-ldflags -X` 注入。需要 Go（DLL 另需 gcc）；`agent-src` 缺失时给出明确错误提示。
- **DLL 形态**（Windows 注入模块）：强制走源码编译（`-buildmode=c-shared`，cgo），导出 `Run` 供宿主进程调用；**Go 宿主加载 Go c-shared DLL 会因双重 runtime 冲突崩溃，必须使用 C/C++ 宿主加载**。

---

## 数据存储

运行数据保存在 **wisp.exe 同目录的 `data/`**：

| 文件 | 说明 |
|------|------|
| `wisp.db` | 监听器 / 会话 / 任务 / 日志 / 传输记录（SQLite） |
| `db_key.bin` | 字段加密密钥（**勿丢失**，丢失后加密字段不可读） |
| `server_rsa.pem` | 服务端 RSA 密钥对（**勿删除**，删除会导致已部署 agent 全部失联） |
| `tls/` | 持久化自签证书（HTTPS 与文件服务器指纹稳定） |
| `screenshots/` | 截图文件，按会话 ID 分目录 |

---

## 测试

```bash
# 服务端（需要 gcc，CGO=1）
CGO_ENABLED=1 go test ./internal/... ./services/...

# agent（独立模块）
cd agent && go test ./...
```

前端检查：`cd frontend && npm run build`（含 tsc 类型检查）。

---

## 主要命令（第一类协议任务）

| ID | 命令 | 说明 |
|----|------|------|
| 1 | shell | 执行单条命令 |
| 2–4 | ls / cd / cat | 目录与文件操作 |
| 5–6 | upload / download | 上传下载（分块） |
| 7–8 | ps / kill | 进程列表 / 结束进程 |
| 9–11 | sysinfo / sleep / exit | 系统信息 / 心跳间隔 / 退出 |
| 12–16 | lsJSON / mkdir / rm / rename / exec | 结构化文件管理 |
| 17–19 | ishell | 交互式 shell |
| 20–22 | RDP | 远程桌面帧流与输入 |
| 23–24 | RCP | 远程控制长连接启停 |
| 25 | screenshot | 单帧截图 |
| 26 | pwd | 当前工作目录 |
| 27 | kill-agent | 结束 agent 进程 |
| 28–31 | reboot / shutdown / logoff / lock | 电脑管理（重启 / 关机 / 注销 / 锁定） |

---

## 相关文档

- [`docs/PROTOCOL-ARCHITECTURE.md`](docs/PROTOCOL-ARCHITECTURE.md) — 三类协议架构详解
- [`docs/REMOTE-CONTROL-PLAN.md`](docs/REMOTE-CONTROL-PLAN.md) — 远程控制设计
- [`docs/STAGER-PLAN.md`](docs/STAGER-PLAN.md) — Payload / stager 设计
- [`docs/FILE-SERVER-PLAN.md`](docs/FILE-SERVER-PLAN.md) — 文件服务器设计

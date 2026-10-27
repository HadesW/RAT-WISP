# WISP++ (wispp)

跨平台 C2 管理控制台，Go teamserver + React 控制台 + Go/Rust 双实现 agent。
支持 HTTP/HTTPS/TCP/RCP/KCP 监听器、多平台 payload 模板生成、文件分发、SOCKS5 / 端口转发、远程桌面、报告导出，以及可接入任意 OpenAI 兼容端点的 **AI 助手面板**。

> **仅用于安全研究与已授权的渗透测试。** 未经授权访问他人系统属违法行为。

## 目录结构

```
wispp/
├── server/          # teamserver（wispd）：监听器 / 会话 / payload / AI 运行时
├── agent/
│   ├── agent-go/    # Go agent（默认，模板交叉编译 6 平台）
│   └── agent-rs/    # Rust agent（新一代，独立 EXE / DLL）
├── client/          # 控制台 SPA（Vite + React 19 + TS + Zustand）
├── shared/protocol/ # 双端共享协议与加密
└── scripts/         # dev-stack.sh 一键环境、demo / e2e 脚本
```

## 环境要求

| 工具 | 版本 |
|------|------|
| Go | 1.25+ |
| Node.js + npm | 20+ |
| Python | 3.x（demo 脚本用） |
| bash | Linux / macOS 自带，Windows 用 Git Bash 或 WSL |

## 快速开始

```bash
# 1) 前端依赖 + 构建（仅首次，产出 client/dist）
cd client && npm install && npm run build && cd ..

# 2) 生成多平台 agent/stager 模板（产出 server/templates，约 85MB）
cd server && go run ./cmd/build_templates && cd ..

# 3) 一键拉起：teamserver + 5 个监听器 + 2 个演示 agent
./scripts/dev-stack.sh
```

更改配置槽读写逻辑后，需要重新编译 teamserver 和 agent 模板，再在控制台重新生成并下载 Payload。已下载的文件不会随源码更新；生成器只接受包含唯一、完整空白配置槽的模板。

脚本会编译 `server/bin/wispd` 与 `agent/bin/wisp-agent`，最后打印带令牌的地址，浏览器打开即登录：

```
http://127.0.0.1:9001/?token=<data/api.token 的内容>
```

令牌每次启动从 `data/api.token` 读取（`data/` 含密钥、PSK、SQLite，已整体 `.gitignore`）。

`data/` 下的 Payload、文件收集结果、AI 配置和数据库均为本地运行数据，不应提交。复制到其他目录的生成 Payload、EXE/DLL、测试产物、常见密钥文件和本地配置同样被忽略；共享配置请使用不含真实凭据的 `.env.example` 或 `agent-*.example.json`。演示 WASM 插件及其签名仍作为测试资源跟踪。

## 手动运行

```bash
# 编译
(cd server && go build -o bin/wispd ./cmd/wispd)
(cd agent/agent-go && go build -o ../../agent/bin/wisp-agent .)

# 启动 teamserver（API + 控制台同源托管在 127.0.0.1:9001）
server/bin/wispd \
  -api 127.0.0.1:9001 \
  -static client/dist \
  -data data \
  -templates server/templates \
  -ai-config data/ai.json

# 启动一个 agent（配置里的 servers 指向你创建的监听器）
agent/bin/wisp-agent -config data/agent-http.json
```

teamserver **不会自行开口**：启动后在控制台「＋ 监听器」页签创建 HTTP / TCP / RCP / KCP 监听器，再在「＋ 生成」里出 payload。

**载荷构建全流程**（控制台「载荷」页）：

1. 选择监听器与平台；需要隐蔽性时勾选「RS 分层」（仅 `windows_amd64`，需同时有运行中的 RCP 监听器）。
2. 设置 sleep / jitter 和备注后点「生成」。产物列表会持久化到 `data/payloads/metas.json`，重启 teamserver 后仍在。
3. staged / RS 分层产物可设置 **stage 有效期（默认 60 分钟，可用 `-stage-ttl` 改默认）** 与 **取件次数（默认 1，`-stage-uses`）**；取件记录与加密 bundle 落在 `data/stage/`，重启后仍可继续取件。次数用尽或过期后点「↻」即可用相同 token 重新上膛，无需重新下载产物。取件路径默认 `/stage`，可用 `-stage-path` 改成中性前缀。
4. 点击某条产物的「投递」：选择在线会话与远端路径，控制台会自动建立 Type2、用 Type3 把文件直接推到目标（无需先下载再上传），并在传输完成后可选择立即运行。
5. 「下载」用于离线投放；「✕」删除产物、磁盘文件并撤销其 stage token。产物名为 16 位随机十六进制，默认投放目录不再包含产品字样（Windows 为 `C:\Windows\Temp\<name>`，POSIX 为 `/tmp/<name>`）。

构建前置检查会直接提示缺少 HTTP / RCP 监听器或模板的情况。模板构建会写入 `go_manifest.json` / `rs_manifest.json`（git 提交、时间、逐文件 SHA-256），控制台展示模板版本并在文件与 manifest 不一致时告警；`WISP_REBUILD_TEMPLATES=1 bash scripts/dev-stack.sh` 可在起栈前重建两套模板。

常用参数（`wispd -h` 查看全部）：

| 参数 | 默认 | 说明 |
|------|------|------|
| `-api` | `127.0.0.1:9001` | 操作端 API + SPA（仅本机） |
| `-data` | `./data` | 运行时数据（密钥 / PSK / token / DB） |
| `-templates` | `./templates` | 预编译 agent 模板目录 |
| `-static` | 空 | 托管 React 构建产物（`client/dist`） |
| `-ai-config` | 空 | AI 配置 JSON，留空 = AI 关闭 |
| `-sleep` / `-jitter` | `5000` / `30` | 新 agent 默认心跳间隔 / 抖动 |
| `-stage-ttl` / `-stage-uses` | `60m` / `1` | staged/RS 载荷默认取件有效期 / 次数 |
| `-stage-path` | `/stage` | stage 取件路径前缀（可改为中性路径） |

## 前端开发模式

两个终端：

```bash
# 终端 1：teamserver（API 在 9001）
server/bin/wispd -api 127.0.0.1:9001 -data data -templates server/templates

# 终端 2：Vite 热更新，/api 自动代理到 9001
cd client && npm run dev
# 打开 http://127.0.0.1:5173/?token=<data/api.token>
```

## 启用 AI 面板

AI **默认关闭**，两种接法：

1. **界面配置（推荐）**：聊天面板左下角「模型选择器」→「＋ 添加模型…」→ 选服务商（阿里云 / DeepSeek / OpenRouter / Ollama / vLLM / 自定义 / mock）→ 贴 Key →「验证并获取模型」→ 选模型 →「保存并使用」，热生效。
2. **配置文件**：写 `data/ai.json` 后带 `-ai-config data/ai.json` 启动：

```json
{
  "enabled": true,
  "active": "默认",
  "profiles": [
    { "name": "默认", "provider": "openai",
      "endpoint": "https://your-endpoint/v1",
      "model": "your-model", "api_key": "" },
    { "name": "离线演示", "provider": "mock", "model": "wispp-mock" }
  ]
}
```

- `provider: openai` = 任意 OpenAI 兼容端点（含本地 Ollama / vLLM）；`mock` 无需 Key，离线演示用。
- **Key 建议留空**，改用环境变量注入：`WISP_AI_KEY=sk-xxx`（优先级更高，不落盘）。
- AI 工具遵循「只读自动执行 / 写操作需审批」：`run_task`、`gen_payload`、`delete_session` 都会在面板弹窗等你批准。

## 测试与检查

```bash
(cd server && go test ./...)
(cd agent/agent-go && go test ./...)
(cd shared/protocol && go test ./...)
(cd client && npm run build)
```

> `server/internal/rcp` 与 `agent` 各有一个 shell 通道测试依赖 POSIX 的 `id` 命令，在 Windows 原生控制台会失败，Git Bash / Linux / macOS 下正常。

## 协作

多人开发统一走「功能分支 → PR → CI 全绿 + 至少 1 人评审 → merge commit 合入 `main`」，`main` 禁止直接 push，完整约定见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

## 文档

| 文档 | 内容 |
|------|------|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | 协作规范：分支/提交/评审/安全审计 checklist |

---

*本项目仅供安全研究与授权测试使用。*

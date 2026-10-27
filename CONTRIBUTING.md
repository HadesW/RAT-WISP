# 协作规范

多人协作统一按本文执行：**功能分支开发 → 本地自检 → PR → CI 全绿 + 人工评审 → merge commit 合入 main**。
`main` 为保护分支，**禁止直接 push**，所有改动必须走 Pull Request。

## 1. 环境要求

| 工具 | 版本 | 用途 |
|------|------|------|
| Go | 1.25+ | server / agent-go / shared-protocol（go.work workspace） |
| Node.js + npm | 20+ | client（Vite + React + TS） |
| bash | — | scripts/*.sh、CI 步骤（Windows 用 Git Bash / WSL） |

## 2. 分支规范

- 从最新的 `main` 切出，命名统一：

  | 前缀 | 用途 |
  |------|------|
  | `feat/<描述>` | 新功能 |
  | `fix/<issue号或描述>` | 修 bug |
  | `docs/<描述>` | 仅文档 |
  | `chore/<描述>` | 构建、依赖、脚手架、CI |
  | `refactor/<描述>` | 重构（不改行为） |

- 描述用小写英文 + 连字符，例：`feat/payload-dll-template`、`fix/rcp-reconnect`
- 分支保持小而聚焦：一个分支只做一件事，做完即开 PR
- **共享分支禁止 force-push**；只有自己的、还没开 PR 的分支才能 rebase -f
- 合并后的分支**保留不删除**，便于回溯；需要清理时由维护者统一处理

## 3. 提交规范（Conventional Commits）

```
<type>: <一句话摘要，≤50 字>

<可选正文：为什么这么改，怎么验证>
```

- `type` 取值：`feat` `fix` `docs` `refactor` `test` `chore` `perf` `ci`
- 摘要写「做了什么」，正文写「为什么」；中英文均可，仓库内以中文为主
- 提交粒度：一个提交是一件可独立说明的事，不混无关改动（格式化、依赖升级单独提）

## 4. 开发流程

```bash
git checkout main && git pull
git checkout -b feat/<描述>

# …编码…

# 本地自检（提交前必须全绿）
gofmt -l server shared agent/agent-go        # 必须无输出
(cd server && go vet ./... && go test ./...)
(cd shared/protocol && go vet ./... && go test ./...)
(cd agent/agent-go && go vet ./... && go test ./...)
(cd client && npm run lint && npm run build)

git add -A && git commit -m "feat: ..."
git push -u origin feat/<描述>
```

之后开 PR（自动带模板），勾完自检清单，等 CI 全绿 + 至少 1 人评审通过，由评审者执行 **merge commit** 合入。

> Windows 说明：本机 `go test` 若在 `server/internal/rcp`、`agent` 报 shell 相关失败，确认已含 `runtime.GOOS == "windows"` 的 `t.Skip`；其余以 CI（Linux）结果为准。

## 5. PR 要求

- 标题与提交规范一致，正文说明动机与影响面，关联 issue 用 `Closes #N`
- **CI 必须全绿**：`Go (ubuntu-latest)`、`Go (windows-latest)`、`client` 三个 job
- **至少 1 名其他成员 approve** 才可合并；作者不能自审自合
- 合并方式固定为 **Create a merge commit**（保留分支历史），不要用 squash / rebase merge
- 合并前如与 main 有冲突，先在分支上 `git rebase main` 解决后再请评审
- 合并后分支保留，不强制删除

## 6. 代码风格

- **Go**：`gofmt` 格式化为准（提交前 `gofmt -l` 无输出）；`go vet` 不得有告警；遵循现有包结构与命名，注释用英文
- **TS/TSX**：以 `npm run lint`（oxlint + react 规则）为准，**error 必须为 0**；hooks 只在组件/自定义 hook 顶层调用，禁止条件调用
- 不引入仓库里没有的重型框架；新增依赖必须在 PR 里说明理由
- 复用现有工具函数与样式（`index.css`、`palette.tsx`、`store.ts`），不重复造轮子

## 7. 安全审计 checklist（评审者逐项过）

- [ ] 无硬编码密钥、token、PSK、内网地址；`data/` 与 `.gitignore` 未被绕过
- [ ] 新增/变更的网络、进程、文件读写行为有明确的授权与边界（本项目仅限授权测试）
- [ ] 认证与校验逻辑（PSK / RCP token / API token）改动附带测试
- [ ] 新增依赖来源可信（官方 registry），且确有必要
- [ ] 无误提交的构建产物、大文件（单文件 >500KB 需在 PR 说明）
- [ ] 默认配置安全（监听地址默认 `127.0.0.1`、密钥 0600、不默认放行）
- [ ] 涉及行为变化的，README / docs 已同步更新

## 8. 文档同步

改了「怎么跑 / 怎么用 / 怎么配」就要改文档：

- 对外用法 → `README.md`
- 只改代码不改文档的 PR，评审者有权要求补充

## 9. 维护者：main 分支保护设置（GitHub 网页）

仓库 Settings → Branches → Add rule（对 `main`）：

1. Require a pull request before merging ✅（Required approving reviews: **1**）
2. Require status checks to pass ✅，勾选 `Go (ubuntu-latest)`、`Go (windows-latest)`、`client`
3. Do not allow bypassing the above settings ✅（管理员也不例外）
4. 可选：Restrict force-pushes ✅、Restrict deletions ✅

设置完成后，任何直接 `git push origin main` 都会被拒绝。

# Rust/WASM Hook 模块

WISP 的统一 hook 框架支持 **Rust 编译的 WebAssembly 模块** 与 gopher-lua 脚本并行运行。
WASM 模块在 Lua 回调**之前**执行（先 WASM 后 Lua），两者都可通过 `ctx.input/output/abort`
改写流量与行为。

## 工作原理

- 服务端启动时加载 `<exeDir>/hooks/*.wasm`（`services/wasmhook`，wazero 纯 Go 运行时，
  无 CGO）
- 每个 hook 事件触发时，Go 把 `{event, phase, input, output, abort}` 序列化为 JSON，
  写入 wasm 线性内存，调用 `wisp_handle(ptr, len)`，读回返回的 JSON 并合并
- 与 Lua 完全同构：`wisp.hook` 与 WASM 模块可同时存在，先 WASM 后 Lua

## 模块 ABI（三个导出函数）

| 导出 | 签名 | 说明 |
|---|---|---|
| `wisp_alloc` | `(size:i32) -> i32` | 分配线性内存，返回偏移 |
| `wisp_handle` | `(ptr:i32, len:i32) -> i32` | 入参 JSON → 返回出参 JSON 指针 |
| `wisp_handle_len` | `() -> i32` | 出参 JSON 长度 |

输入/输出 JSON 形状与 Lua 的 `ctx` 相同：
```json
{ "event": "listener:checkin", "phase": "pre",
  "abort": false,
  "input": { "ip": "...", "path": "...", "headers": {...} },
  "output": { "response_headers": {...} } }
```

## 编译

```bash
cd src/wasmhooks/rust-template
rustup target add wasm32-wasip1        # 或 wasm32-unknown-unknown
cargo build --release --target wasm32-wasip1
mkdir -p <wisp>/hooks
cp target/wasm32-wasip1/release/wisp_hook.wasm <wisp>/hooks/mydetector.wasm
# 重启 wisp，模块自动加载
```

wazero 自带 WASI `proc_exit` 等 import，`wasm32-wasip1` 目标可直接实例化。

## 示例（模板默认逻辑）

模板 `src/lib.rs` 的 `handle()` 演示两类用法：
1. 给 `listener:checkin` 响应加 `X-Wasm: rust-module` 头
2. 对 `ip == "10.0.0.66"` 置 `abort = true` 阻断

## 测试

`services/wasmhook/wasmhook_test.go` 用手写 WAT 编译的测试模块验证加载与 abort 合并；
`services/hook_test.go` 的 `TestWasmHookDispatch` 验证经统一分发 WASM abort 生效。

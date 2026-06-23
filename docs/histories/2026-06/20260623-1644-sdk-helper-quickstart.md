## [2026-06-23 16:44] | Task: SDK helper quickstart

### 🤖 Execution Context

- **Agent ID**: `Codex`
- **Base Model**: `GPT-5`
- **Runtime**: `Codex CLI`

### 📥 User Query

> 支持 SDK 模式，保留 CLI 能力；增加 pkg 侧 helper 能力，并在根目录新增每个例子一个目录的 examples quickstart，示例要从使用方视角直接 import Go package，不依赖当前仓库相对路径。阶段性成果验证后提交并推送。

### 🛠 Changes Overview

**Scope:** `pkg/sandbox`, helper dispatch, examples, docs

**Key Actions:**

- **SDK helper dispatch**: 新增 `sandbox.MaybeRunHelper`、`RunHelper` 和 `HelperCommand`，让上层应用自己的二进制可以承接 Linux bridge / Windows runner 内部 helper 命令。
- **Internal helper protocol**: 新增统一 `__sandbox-local-helper` 前缀，并让 Linux allowlist bridge、seccomp wrapper、Windows runner 通过同一协议进入 helper。
- **Quickstart example**: 新增 `examples/quickstart` 独立 Go module，直接 require 远端 `github.com/iFurySt/sandbox-local`，展示 `HelperPath: os.Args[0]` 的 SDK 模式。
- **Docs sync**: 更新中英文 README、架构文档和发布记录，说明 SDK self-helper 用法。

### 🧠 Design Intent (Why)

SDK 使用方只 `go get` 库时，Linux allowlist bridge 和 Windows runner 仍需要 helper 进程进入内部命令。让上层应用在 `main()` 顶部调用 `sandbox.MaybeRunHelper()`，可以复用自身二进制作为 helper，避免额外安装 CLI，同时保留 `sandbox-local` CLI 的原有调试和最终用户入口。

### 📁 Files Modified

- `pkg/sandbox/helper.go`
- `internal/helpercmd/helpercmd.go`
- `internal/helperprotocol/protocol.go`
- `internal/backend/linux/backend.go`
- `internal/backend/windows/backend.go`
- `internal/linuxbridge/bridge_linux.go`
- `internal/cli/root.go`
- `examples/quickstart/`
- `README.md`
- `README.zh-CN.md`
- `docs/ARCHITECTURE.md`
- `docs/design-docs/go-sandbox-runtime-architecture.md`
- `docs/releases/feature-release-notes.md`

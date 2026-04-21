# 架构总览

`sandbox-local` 是一个用 Go + Cobra 实现的跨平台本地 sandbox runtime。它会同时提供：

- Go SDK：供上层客户端应用直接调用。
- CLI：供本地调试、自动化脚本和最终用户直接运行。

主路线是封装主流 OS 的原生隔离能力，而不是把 Docker 作为默认 sandbox 实现。详细设计见 `docs/design-docs/go-sandbox-runtime-architecture.md`。

## 目标运行模型

```text
上层客户端应用 / CLI
        |
        v
pkg/sandbox              # 稳定 SDK facade
        |
        v
internal/engine          # 策略合并、后端选择、运行编排、cleanup
        |
        +-- internal/backend/macos    # Seatbelt / sandbox-exec
        +-- internal/backend/linux    # bubblewrap / namespaces / seccomp
        +-- internal/backend/windows  # temporary local user / ACL / firewall / Job Object
        |
        +-- internal/network          # host proxy / bridge / allowlist
        +-- internal/fsx              # 路径规范化和保护路径
        +-- internal/process          # 进程启动、stdio、进程树清理
```

## 预期仓库结构

- `cmd/sandbox-local/`：Cobra CLI 入口，只做参数解析和命令组织。
- `pkg/sandbox/`：对外 Go SDK，隐藏平台实现细节。
- `internal/cli/`：Cobra command 组装，调用 `pkg/sandbox`。
- `internal/engine/`：跨平台运行编排、后端选择和生命周期管理。
- `internal/backend/`：平台后端实现，使用 build tags 隔离 OS 专属代码。
- `internal/config/`：CLI 配置文件加载、合并和校验。
- `internal/fsx/`：路径 canonicalization、symlink/junction 防绕过、默认敏感路径保护。
- `internal/network/`：HTTP/SOCKS proxy、parent proxy、Unix socket / TCP bridge 抽象。
- `internal/process/`：进程启动、PTY、超时、进程树清理、Windows Job Object 封装。
- `internal/diagnostics/`：`doctor`、能力报告、脱敏执行计划。
- `configs/examples/`：示例 sandbox policy。
- `docs/`：架构、计划、历史、发布和本地知识库。
- `scripts/`：仓库级自动化脚本。

## 依赖边界

- `cmd/sandbox-local` 不能直接依赖平台后端。
- `internal/cli` 只能通过 `pkg/sandbox` 使用 sandbox 能力。
- `pkg/sandbox` 是稳定 SDK 入口，可以调用 `internal/engine`。
- `internal/backend/*` 不反向依赖 `pkg/sandbox`，避免 Go import cycle。
- macOS、Linux、Windows 后端只通过 `internal/backend.Backend` 接口暴露能力。

## 平台边界

- macOS：固定调用 `/usr/bin/sandbox-exec`，动态生成 Seatbelt profile。
- Linux：优先 bubblewrap / namespaces，后续补 seccomp 和 managed proxy bridge。
- Windows：当前使用临时本地用户作为 sandbox identity，通过 ACL/DACL 表达文件读写策略，用 Job Object 管住进程树，并通过 Windows Firewall 的 per-user 规则实现 `offline` 网络。当前 UTM Windows arm64 环境中，备用凭据启动部分系统程序会返回 `0xC0000142`，Windows 后端仍需补一条更稳定的进程启动路径。

任何平台无法强制执行的策略，都必须通过 capability report 或运行错误显式暴露，不能静默当作成功。

## 当前实现状态

- 已实现 Go module、SDK facade、Cobra CLI、配置加载和基础单元测试。
- 已实现 macOS Seatbelt 后端的最小闭环：文件写 allow/deny、network `offline` / `allowlist` / `open`。`allowlist` 通过 host-managed HTTP/HTTPS proxy 强制执行，Seatbelt 只放行该本地代理端口。
- 已实现 Linux bubblewrap 后端的最小闭环：只读根、writable roots、deny remount/mask、network `offline` / `allowlist` / `open`。`allowlist` 使用 `--unshare-net`、sandbox 内 loopback bridge、host Unix socket proxy 和 seccomp exec wrapper，阻断直接 AF_UNIX/socketpair 绕过。
- 已实现 Windows local-user 后端的策略骨架：临时本地用户、ACL read/write allow/deny、Job Object cleanup、network `offline` / `open`。在本轮 UTM Windows arm64 复验中，`LogonUser/CreateProcessWithTokenW`、PowerShell `Start-Process -Credential`、batch token 和 OpenSSH 临时用户路径均未能稳定启动 `cmd.exe` / `whoami.exe` / `powershell.exe`，典型退出码为 `0xC0000142`；Windows `allowlist` 仍未支持，`doctor` 会显式报告。
- Release packaging 已从模板元数据包切换为真实 Go 二进制归档，覆盖 darwin/linux/windows 的 arm64/amd64。

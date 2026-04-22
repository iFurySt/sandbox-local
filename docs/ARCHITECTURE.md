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
        +-- internal/backend/windows  # persistent local user / ACL / firewall / scheduled task runner
        |
        +-- internal/network          # host proxy / bridge / allowlist
        +-- internal/fsx              # 路径规范化和保护路径
        +-- internal/helper           # SDK 场景下解析 sandbox-local helper binary
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
- `internal/helper/`：解析 CLI/helper binary，保证 SDK 上层应用不会被误当成 internal helper 重新执行。
- `internal/network/`：HTTP/SOCKS proxy、parent proxy、Unix socket / TCP bridge 抽象。
- `internal/process/`：进程启动、PTY、超时和进程树清理。
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
- Linux：使用 bubblewrap / namespaces 表达 filesystem 与 network 隔离；`allowlist` 通过 sandbox 内 loopback bridge、host-managed proxy 和 seccomp exec wrapper 阻断直接 socket 绕过。
- Windows：当前使用持久但默认禁用的本地用户 `sandboxlocal` 作为 sandbox identity；`sandbox-local setup windows` 可预创建/检查账户、batch logon right、Task Scheduler、Firewall 和 OpenSSH 状态。每次运行前重置随机密码并启用账户，运行后禁用账户。文件策略通过 ACL/DACL 表达，进程启动通过一次性 Windows Scheduled Task runner 规避 UTM/SSH service 场景下 `CreateProcessWithTokenW` 的 `0xC0000142` 兼容性问题，`offline` 与 `allowlist` 网络通过 Windows Firewall per-user 规则阻断直连，allowlist 流量走 host-managed HTTP/HTTPS proxy。

任何平台无法强制执行的策略，都必须通过 capability report 或运行错误显式暴露，不能静默当作成功。

## 当前实现状态

- 已实现 Go module、SDK facade、Cobra CLI、配置加载和基础单元测试。
- 已实现 macOS Seatbelt 后端闭环：文件写 allow/deny、文件 read deny、network `offline` / `allowlist` / `open`。`allowlist` 通过 host-managed HTTP/HTTPS proxy 强制执行，Seatbelt 只放行该本地代理端口；文件路径会 canonicalize 现有 symlink 前缀。
- 已实现 Linux bubblewrap 后端闭环：只读根、writable roots、deny remount/mask、network `offline` / `allowlist` / `open`。`allowlist` 使用 `--unshare-net`、sandbox 内 loopback bridge、host Unix socket proxy 和 seccomp exec wrapper，阻断直接 AF_UNIX/socketpair 绕过；SDK 场景通过 `Options.HelperPath` 或 `SANDBOX_LOCAL_HELPER` 指向 helper binary。
- 已实现 Windows local-user 后端闭环：持久禁用账户 `sandboxlocal`、`setup windows`、ACL read/write allow/deny、一次性 scheduled task runner、network `offline` / `allowlist` / `open`。UTM Windows arm64 上已验证 SDK E2E、CLI allowlist 允许/拒绝、`--noproxy` 直连绕过阻断和 cleanup；`doctor` 会提示 Windows allowlist 依赖 host proxy 与 per-user firewall，loopback 会保留给 managed proxy。
- Release packaging 已从模板元数据包切换为真实 Go 二进制归档，覆盖 darwin/linux/windows 的 arm64/amd64。

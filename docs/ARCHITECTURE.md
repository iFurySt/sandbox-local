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
        +-- internal/backend/windows  # AppContainer (standard user) / local runner (elevated) / ACL
        |
        +-- internal/network          # host proxy / bridge / allowlist
        +-- internal/fsx              # 路径规范化和保护路径
        +-- internal/appcontainer     # per-user profiles / restricted token / private desktop / job
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

- macOS：`Policy.Seatbelt.DefaultAction` 支持显式选择 `allow` 基线，省略或 `deny` 保持现有默认拒绝行为；两种基线均保留文件与网络规则。固定调用 `/usr/bin/sandbox-exec -p`，将完整动态生成的 Seatbelt profile 作为单个参数传递，不创建临时策略文件。策略仍受 macOS 进程参数大小上限约束；超出上限的任意大策略不受支持，启动会返回系统错误。
- Linux：使用 bubblewrap / namespaces 表达 filesystem 与 network 隔离；`allowlist` 通过 sandbox 内 loopback bridge、host-managed proxy 和 seccomp exec wrapper 阻断直接 socket 绕过。
- Windows 普通用户：自动选择 `windows-appcontainer`，每次调用创建并回收当前用户的 AppContainer profile。package SID 的局部 grant 与普通 restricting SID 的 deny 共同约束文件访问；跨进程文件锁串行化 ACL 更新，清理只移除当前身份的 ACE。helper 使用独立 desktop、管道 stdio 和 Job Object 启动进程树；offline 不授予网络 capability，open 保留 loopback 隔离，allowlist 显式拒绝。PowerShell 需要交互式用户会话。
- Windows 提权进程：`sandbox-local setup windows` 保留既有预检入口。每次 `Run` 使用独立的临时本地账户、随机 capability SID、私有 window station 和 desktop。broker 不加载用户配置文件；真实命令使用 `WRITE_RESTRICTED` token，保留 capability、临时账户、logon SID 和 Everyone 作为 restricting SID，仍排除内置 Users 组。`offline` 和 `allowlist` 使用本次账户对应的出站防火墙规则，allowlist 流量仍走 host-managed HTTP/HTTPS proxy。

任何平台无法强制执行的策略，都必须通过 capability report 或运行错误显式暴露，不能静默当作成功。

Windows 管理员后端对允许路径的父目录仅临时授予不继承的属性读取、遍历与同步句柄权限，供 Node 等运行时解析真实路径；不允许列目录或读写旁支文件。父目录 DACL 通过单对象原生 API 更新与恢复，保留继承标志，不递归处理父目录树。系统拥有且不能修改的父目录沿用已有权限并返回 warning。

Windows 管理员后端使用 `Local\sandbox-local-windows-backend` 命名 mutex 协调 ACL 的更新和清理，不覆盖普通命令的执行阶段。
清理只删除本次账户和 capability SID 的条目；若策略覆盖原本为空的 DACL，则沿用完整执行锁，直到恢复原状。
mutex 由固定在同一 OS 线程的专用 goroutine 获取和释放，排队获取时响应 context 取消。

管理员后端为每次调用创建独立受保护的传输目录。broker 在降权前打开 stdin/stdout/stderr，不改变原始字节，
并独立报告启动失败和业务退出码。运行期间按字节偏移转发输出；退出后仅转发剩余部分。
私有 window station 的切换只发生在单次调用的 controller 进程，不修改宿主的共享 desktop。

受限命令及后代由 Job Object 管理；controller 退出时回收 broker 及其进程树，随后清理本次 ACL、网络规则、传输目录和临时账户。
取消后的 IPC 清理对短暂的共享冲突、访问拒绝和非空目录错误做有界重试；永久失败仍显式返回。

Windows 执行回归位于 `tests/e2e/windows_*_test.go`。跨编译验证可通过
`SANDBOX_LOCAL_TEST_HELPER` 和 `SANDBOX_LOCAL_TEST_COMMAND` 指定原生 helper 与命令 fixture；
fixture 源码为 `tests/e2e/testdata/command`。执行测试时保持系统防护开启，任何临时排除均需测试机所有者明确授权。

## 当前实现状态

- 已实现 Go module、SDK facade、Cobra CLI、配置加载和基础单元测试。
- 已实现 macOS Seatbelt 后端闭环：文件写 allow/deny、文件 read deny、network `offline` / `allowlist` / `open`。`allowlist` 通过 host-managed HTTP/HTTPS proxy 强制执行，Seatbelt 只放行该本地代理端口；文件路径会 canonicalize 现有 symlink 前缀。
- 已实现 Linux bubblewrap 后端闭环：只读根、writable roots、deny remount/mask、network `offline` / `allowlist` / `open`。`allowlist` 使用 `--unshare-net`、sandbox 内 loopback bridge、host Unix socket proxy 和 seccomp exec wrapper，阻断直接 AF_UNIX/socketpair 绕过；SDK 场景通过 `sandbox.MaybeRunHelper()` 让上层应用二进制承接 internal helper dispatch，并通过 `Options.HelperPath` 或 `SANDBOX_LOCAL_HELPER` 指向该 helper-capable binary。
- Windows 普通用户后端无需管理员初始化；限制与执行要求见 README。提权 local-user 后端支持单次调用身份、私有桌面、受限 token 和受保护的增量输出。两者继续使用各自的文件与网络策略，不允许失败后静默放宽权限。
- 仓库当前只保留基础 CI；release、SBOM 和 provenance 流水线已收口为后续明确发布需求后再接入。

### Windows invocation ownership and cleanup

The elevated host serializes ACL mutation, not the command lifetime. It also takes the existing same-user AppContainer ACL lock so the two policy writers cannot overwrite one another. Rollback removes only the invocation account/capability SID's entries. Replacing a null DACL still retains the mutation locks until full restoration.

The single-invocation controller creates a private station/desktop and starts a profile-free broker suspended. The broker receives a system environment block instead of inheriting controller credentials; requested variables arrive through protected IPC. The controller owns the broker's Job Object, waits for zero active processes on termination, then releases desktop objects. Host cleanup removes transport files, per-account firewall rules, ACL entries and the account, returning cleanup failures explicitly.

# Go sandbox runtime 架构设计

本文定义 `sandbox-local` 从模板仓库落成跨平台 sandbox runtime 的初始目录和架构。目标是用 Go + Cobra 提供一套 SDK 与 CLI，让上层客户端应用用统一 API 运行受限进程，而不需要理解 macOS、Linux、Windows 的原生隔离细节。

参考输入：

- `/tmp/sandbox_repo_reference.md`
- `/Users/bytedance/projects/github/sandbox-runtime`
- `/Users/bytedance/projects/github/codex`

## 目标

- 提供一个 Go SDK，作为所有上层客户端应用的主入口。
- 提供一个 Cobra CLI，作为 SDK 能力的薄封装和本地调试入口。
- 默认使用 OS-native sandbox，不把 Docker 作为主实现。
- 对外暴露稳定的策略、运行、诊断模型；把 Seatbelt、bubblewrap、seccomp、Windows token / ACL / firewall 等细节隐藏在内部后端。
- 覆盖 macOS、Linux、Windows，并在每个平台上明确能力等级，不能强制执行的策略必须显式报错或降级记录。

## 非目标

- 第一阶段不实现容器编排平台。
- 第一阶段不承诺三端能力完全等价，只承诺同一份策略能得到明确的执行计划或明确错误。
- 不把 sandbox 策略和上层产品权限系统耦合。

## 顶层目录

```text
.
├── cmd/
│   └── sandbox-local/             # Cobra CLI 入口
├── pkg/
│   └── sandbox/                   # 对外 Go SDK；只暴露跨平台模型
├── internal/
│   ├── cli/                       # Cobra command 组装，调用 pkg/sandbox
│   ├── engine/                    # Manager、backend selection、运行编排
│   ├── model/                     # 内部 request / policy / result / capability
│   ├── backend/
│   │   ├── backend.go             # 后端接口和注册
│   │   ├── macos/                 # Seatbelt / sandbox-exec
│   │   ├── linux/                 # bubblewrap / namespaces / seccomp / proxy bridge
│   │   ├── windows/               # local user / ACL / firewall / Job Object / helper
│   │   └── noop/                  # 显式 no-sandbox 后端，仅用于调试和测试
│   ├── config/                    # CLI config 文件加载、合并、校验
│   ├── fsx/                       # 路径规范化、symlink/junction 防绕过、默认保护路径
│   ├── network/                   # host proxy、allowlist、parent proxy、UDS bridge 抽象
│   ├── process/                   # spawn、stdio、PTY、进程树清理、Windows Job Object 封装
│   ├── diagnostics/               # doctor、capability report、sanitized execution plan
│   └── testkit/                   # 供集成测试复用的 helper
├── configs/
│   └── examples/                  # 示例策略文件
├── docs/
│   ├── ARCHITECTURE.md
│   └── design-docs/
└── scripts/                       # CI、release、代码生成和本地验证脚本
```

## 依赖方向

```text
cmd/sandbox-local
  -> internal/cli
  -> pkg/sandbox
  -> internal/engine
  -> internal/backend + internal/network + internal/fsx + internal/process
```

约束：

- `pkg/sandbox` 是唯一稳定 SDK 入口。
- `cmd/sandbox-local` 不直接调用任何平台后端，只通过 SDK 运行。
- `internal/backend/*` 不反向依赖 `pkg/sandbox`，避免 public package 与 internal implementation 形成 Go import cycle。
- OS 专属文件用 build tags 隔离，例如 `backend_darwin.go`、`backend_linux.go`、`backend_windows.go`。

## SDK 形态

`pkg/sandbox` 暴露少量稳定对象：

```go
type Manager struct { ... }

type Request struct {
    Command []string
    Cwd     string
    Env     map[string]string
    Policy  Policy
    Stdio   Stdio
}

type Policy struct {
    Filesystem FilesystemPolicy
    Network    NetworkPolicy
    Process    ProcessPolicy
}

type Options struct {
    BackendPreference BackendPreference
    Enforcement       EnforcementMode
    Logger            Logger
    EventSink         EventSink
}

func NewManager(opts Options) (*Manager, error)
func (m *Manager) Run(ctx context.Context, req Request) (*Result, error)
func (m *Manager) Prepare(ctx context.Context, req Request) (*Plan, error)
func (m *Manager) Check(ctx context.Context) (*CapabilityReport, error)
func (m *Manager) Close() error
```

设计点：

- `Run` 是上层客户端最常用入口。
- `Prepare` 返回脱敏后的执行计划，供 CLI `debug plan` 和客户端诊断使用。
- `Check` 返回当前平台能力、缺失依赖和可用后端。
- `EnforcementMode` 至少包含 `Require` 与 `BestEffort`。默认推荐 `Require`，避免“以为被隔离，实际没隔离”。

## 策略模型

策略保持 OS-neutral：

```text
FilesystemPolicy
  - read deny / read allow carveout
  - write allowlist
  - write deny override
  - protected defaults: .git, .codex, .agents, credential/key material

NetworkPolicy
  - mode: offline | allowlist | open
  - allowed hosts/domains
  - denied hosts/domains
  - unix socket allowlist
  - local binding policy
  - parent proxy / managed proxy policy

ProcessPolicy
  - timeout
  - kill process tree on close
  - PTY / non-PTY
  - environment sanitization
```

默认值：

- 文件读取先允许，支持 deny 后 allow carveout，便于开发工具读取系统依赖。
- 文件写入默认拒绝，只允许显式 writable roots。
- 网络默认拒绝。allowlist 流量走 host-managed proxy。
- 敏感目录在 writable root 之下也要重新只读或屏蔽，例如 `.git`、`.codex`、`.agents`。

## 后端接口

`internal/backend` 提供统一接口：

```go
type Backend interface {
    Name() string
    Platform() model.Platform
    Check(context.Context) model.CapabilityReport
    Prepare(context.Context, model.Request) (model.PreparedCommand, model.Cleanup, error)
}
```

`internal/engine` 负责：

- 合并默认策略、配置文件和请求级策略。
- 选择可用后端。
- 启动网络代理或桥接器。
- 调用后端生成 sandboxed command。
- 运行进程、转发 stdio、收集退出状态。
- 做 cleanup，确保整个进程树被清理。

## 平台后端

### macOS

目录：

```text
internal/backend/macos/
├── backend_darwin.go
├── seatbelt.go
├── profile.go
└── policies/
    ├── base.sbpl
    └── network.sbpl
```

实现路线：

- 固定调用 `/usr/bin/sandbox-exec`，不从 `PATH` 查找。
- 动态生成 Seatbelt profile，表达 filesystem、network、Unix socket 和必要的 Mach lookup 规则。
- 网络 allowlist 通过 host proxy 统一裁决，只允许 sandboxed process 访问本地代理端口。
- 可选接入 macOS sandbox violation log，统一转换为 SDK event。

### Linux

目录：

```text
internal/backend/linux/
├── backend_linux.go
├── bwrap.go
├── mount_plan.go
├── seccomp/
└── proxybridge/
```

实现路线：

- 优先使用系统 `bwrap`；后续 release 可提供受控 vendored helper。
- mount namespace 中默认 `--ro-bind / /`，再按策略 bind writable roots。
- 对 deny paths、glob 展开结果、symlink-in-path、missing protected components 做 mask。
- restricted network 默认 `--unshare-net`。
- managed proxy 模式下使用 host proxy + UDS/TCP bridge；bridge 建立后用 seccomp 限制绕过路径。
- 对 WSL1、缺 user namespace、缺 bwrap 等场景在 `Check` 中给出明确 capability report。

### Windows

目录：

```text
internal/backend/windows/
├── backend_windows.go
├── token.go
├── acl.go
├── firewall.go
├── setup.go
├── runner.go
└── job.go
```

实现路线：

- 当前最小闭环使用每次运行创建的临时本地用户作为 sandbox identity，并用机器级 mutex 串行化 ACL setup / cleanup。
- 文件权限通过 ACL / DACL / ACE 表达 allow / deny，运行后恢复原始 DACL。
- Job Object 使用 `KILL_ON_JOB_CLOSE` 管住子进程生命周期。
- `offline` 网络通过 Windows Firewall per-user outbound block 规则实现；规则使用临时用户 SID 的 SDDL 表达，运行后清理。
- `allowlist` 网络暂未实现，`CapabilityReport.NetworkModes` 只暴露 `offline` 与 `open`，请求 allowlist 时必须失败。
- 当前 UTM Windows arm64 复验暴露备用凭据启动兼容性阻塞：`LogonUser/CreateProcessWithTokenW` 与 PowerShell `Start-Process -Credential` 均会让部分系统程序以 `0xC0000142` 退出；后续 Windows 后端需要评估持久 sandbox identity、服务 helper、restricted token/AppContainer 或 WFP 方案。
- 后续可以把每次创建临时用户优化为 `sandbox-local setup windows` 的持久 sandbox identity，减少运行时高权限操作。

## CLI 形态

CLI 由 Cobra 组织，所有命令通过 `pkg/sandbox`：

```text
sandbox-local run [flags] -- <command...>
sandbox-local doctor
sandbox-local policy init
sandbox-local policy validate <file>
sandbox-local policy explain <file>
sandbox-local debug plan [flags] -- <command...>
sandbox-local setup windows     # future: persistent Windows sandbox identity
sandbox-local version
```

配置文件建议从 `sandbox-local.yaml` 起步，也支持 `--policy` 指定路径。SDK 调用不依赖配置文件。

## 配置示例

```yaml
version: 1
profiles:
  default:
    filesystem:
      read:
        deny:
          - "~/.ssh"
          - "~/.aws"
        allow:
          - "."
      write:
        allow:
          - "."
          - "${TMPDIR}"
        deny:
          - ".git"
          - ".codex"
          - ".agents"
    network:
      mode: offline
      allow: []
      deny: []
    process:
      timeout: 30s
```

## 诊断和可观测性

- SDK 输出结构化 event：backend selected、dependency missing、policy downgraded、network denied、filesystem denied、process exited。
- CLI 默认人类可读，`--json` 输出机器可读。
- 所有 debug plan 必须脱敏路径中的 home、token、proxy credential。
- 拒绝原因统一映射为稳定错误类型，便于上层应用做 UI 呈现。

## 测试策略

- 单元测试：策略合并、domain pattern、path canonicalization、默认保护路径。
- Golden tests：macOS SBPL、Linux bwrap argv、Windows ACL/firewall plan。
- 集成测试：按 build tag 或环境变量启用真实 sandbox，避免在不支持的平台误报。
- 安全回归测试：symlink/junction、missing path、glob、IP canonicalization、localhost/proxy 绕过。
- CLI smoke：`run`、`doctor`、`policy validate` 在 CI 三平台运行。

## 分阶段落地

1. 初始化 Go module、Cobra CLI 骨架、SDK facade、policy model、noop backend、CLI smoke test。
2. 落 macOS Seatbelt 后端，支持文件策略和 offline / allowlist 网络代理。
3. 落 Linux bubblewrap 后端，先支持 filesystem 与 offline，再补 managed proxy 与 seccomp。
4. 落 Windows restricted-token 后端，补 setup helper、ACL、firewall、Job Object。
5. 补 release 矩阵、SBOM、provenance、安装脚本和跨平台 E2E。

## 关键风险

- 三个平台 enforcement 不完全等价。应通过 `CapabilityReport` 与 `EnforcementMode` 把差异显式化。
- Linux 依赖 user namespace / bwrap，部分企业环境或容器内会不可用。`doctor` 必须提前暴露。
- Windows 强网络控制需要高权限 setup。运行时不能静默降级。
- 路径绕过是核心安全风险，必须优先做 canonicalization、symlink / junction、missing path 测试。
- 网络 allowlist 不能只做字符串后缀匹配，需要处理 IP、localhost、IDNA、控制字符和代理 credential 脱敏。

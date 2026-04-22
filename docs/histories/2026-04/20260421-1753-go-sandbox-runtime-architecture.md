# Go sandbox runtime 架构设计与首轮实现

## 用户诉求

参考本地 sandbox runtime 与 Codex 的 sandbox 实现，为当前仓库设计并开始实现 Go + Cobra 的目录和架构。目标是未来通过 SDK 和 CLI 服务上层客户端应用，隐藏 macOS、Linux、Windows 的实现细节，并采用 Apache-2.0 许可。

## 主要改动

- 新增 `docs/design-docs/go-sandbox-runtime-architecture.md`，定义 Go SDK、Cobra CLI、平台后端、策略模型、诊断、测试和分阶段落地方案。
- 更新 `docs/ARCHITECTURE.md`，把模板占位替换为当前项目的真实顶层架构。
- 新增 `docs/exec-plans/active/go-sandbox-runtime.md`，记录后续实现里程碑、风险和验证方式。
- 更新 `docs/design-docs/index.md` 与 `docs/QUALITY_SCORE.md`，同步文档索引和质量水位。
- 切换仓库许可到 Apache-2.0，并同步 README 许可证链接。
- 新增 Go module、Cobra CLI、SDK facade、policy config、engine、backend selection。
- 新增 macOS Seatbelt 后端和 Linux bubblewrap 后端的最小可运行实现。
- 新增 macOS/Linux 网络 allowlist：host-managed HTTP/HTTPS proxy、macOS Seatbelt loopback 限制、Linux UDS bridge 和 seccomp exec wrapper。
- 新增 Windows local-user 后端，使用临时本地用户、ACL/DACL、Job Object 和 per-user Firewall 规则实现最小闭环。
- Windows 后端 cleanup 会恢复 ACL、删除临时用户、删除 per-user Firewall 规则，并补充清理临时用户 profile 目录。
- Windows runner 增加请求环境 JSON 转发，改为用 `LogonUserW`、token environment block 和 `CreateProcessWithTokenW` 启动目标命令，并修复 Windows setup mutex 在已存在时误报错误的问题。
- 复验 Windows UTM arm64 时发现备用凭据进程启动阻塞：`cmd.exe`、`whoami.exe`、`where.exe`、`powershell.exe` 可能返回 `0xC0000142`；对照验证显示 PowerShell `Start-Process -Credential` 也会复现，batch token 和 OpenSSH 临时用户路径未解决，因此 Windows E2E 仍不能标为完备。
- 新增 CLI/config/path/SDK 单元测试，并把 `go test ./...` 接入 `scripts/ci.sh`。
- 新增 `configs/examples/default.yaml`。
- 将 `scripts/release-package.sh` 从模板元数据包替换为真实跨平台 Go 二进制归档。
- 更新执行计划、架构文档、质量评分和发布记录，记录 Windows 真实 enforcement 状态与剩余 allowlist 缺口。

## 设计动机

- 参考实现都以 OS-native sandbox 为主路径，不把 Docker 作为默认隔离机制。
- SDK 和 CLI 应复用同一执行路径，避免平台后端能力在不同入口漂移。
- 三个平台的 enforcement 能力不完全等价，因此需要用 capability report 和 enforcement mode 显式表达差异。
- Windows 第一轮选择临时本地用户而不是仅 restricted token，是为了在当前 CLI 中实际落地 ACL 与 per-user firewall enforcement；后续可用 setup 命令优化为持久 sandbox identity。
- Windows profile 目录需要显式清理，因为 `net user /delete` 不会删除 `LOGON_WITH_PROFILE` 创建的用户目录。
- 当前 Windows arm64/UTM 的备用凭据启动问题不应被隐藏为成功；后续需要改为更稳定的 Windows helper、持久 identity、restricted token/AppContainer 或 WFP 方案。

## 2026-04-22 补充

- 复验新装 Windows/UTM 环境，确认 SSH、管理员令牌、`doctor` 和 noop backend 正常。
- 复现 `cmd.exe` 在真实 Windows 后端下返回 `0xC0000142`；对照验证 PowerShell `Start-Process -Credential` 同样返回 `-1073741502`，说明问题不局限于 Go runner。
- Windows 后端从 per-run 临时用户改为持久但默认禁用的 `sandboxlocal` identity；每次运行前重置随机密码、启用账号并授予 `SeBatchLogonRight`，运行后撤销本轮 right 并禁用账号。
- Windows runner 删除 `CreateProcessWithTokenW` 直启路径，改为注册一次性 Scheduled Task，在 task 中运行 PowerShell wrapper，并回放 stdout/stderr/exit code。
- 修正 PowerShell 5.1 重定向 UTF-16LE 输出回放，以及 native stderr 被包装成 PowerShell ErrorRecord 的问题。
- 复验 Windows：真实后端 smoke、`.git` 写拒绝、`--deny-read`、`--network open`、默认 offline 均通过；cleanup 后不再新增 `sbx*` 临时用户，保留 disabled `sandboxlocal` 作为预期状态。
- 同步架构文档、执行计划、质量评分和发布记录，把 Windows `0xC0000142` 阻塞改为已处理，并记录后续 `setup windows` 与 allowlist/WFP TODO。

## 受影响文件

- `docs/ARCHITECTURE.md`
- `docs/design-docs/go-sandbox-runtime-architecture.md`
- `docs/design-docs/index.md`
- `docs/exec-plans/active/go-sandbox-runtime.md`
- `docs/QUALITY_SCORE.md`
- `LICENSE`
- `README.md`
- `go.mod`
- `go.sum`
- `cmd/sandbox-local/`
- `pkg/sandbox/`
- `internal/`
- `configs/examples/default.yaml`
- `scripts/ci.sh`
- `scripts/release-package.sh`
- `docs/releases/feature-release-notes.md`

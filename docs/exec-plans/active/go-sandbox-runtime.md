# Go sandbox runtime 落地计划

## 目标

把 `sandbox-local` 落成一个 Go + Cobra 跨平台 sandbox runtime，同时提供稳定 Go SDK 和 CLI。上层客户端应用只依赖统一策略和运行接口，不直接处理 macOS、Linux、Windows 的原生隔离差异。

## 范围

- 包含：
  - Go module、Cobra CLI 和 SDK facade。
  - OS-neutral policy、capability report、execution plan、result/error 模型。
  - macOS Seatbelt、Linux bubblewrap、Windows local-user/ACL/firewall 后端的分阶段实现。
  - CLI `run`、`doctor`、`setup`、`policy`、`debug plan`。
  - 跨平台测试、release、SBOM、provenance 接入。
- 不包含：
  - Docker 作为默认 sandbox 实现。
  - 与具体上层产品权限系统深度耦合。
  - 第一阶段保证三端能力完全等价。

## 背景

- 相关文档：
  - `docs/design-docs/go-sandbox-runtime-architecture.md`
  - `docs/ARCHITECTURE.md`
  - `/tmp/sandbox_repo_reference.md`
- 相关参考路径：
  - `/Users/bytedance/projects/github/sandbox-runtime`
  - `/Users/bytedance/projects/github/codex`
- 已知约束：
  - 主实现必须隐藏 OS 细节，对 SDK 和 CLI 暴露统一抽象。
  - 不能把无法强制执行的策略静默当作成功。
  - 上层客户端需要开箱即用的 SDK API，而 CLI 也必须复用同一执行路径。

## 风险

- 风险：三端 sandbox enforcement 不完全等价。
  缓解方式：引入 `CapabilityReport` 和 `EnforcementMode`，默认 `Require`。
- 风险：Linux 环境可能缺少 user namespace 或 bubblewrap。
  缓解方式：`doctor` 提前检测；后续评估 vendored helper。
- 风险：Windows 强网络限制和 sandbox identity setup 需要高权限。
  缓解方式：当前使用持久但默认禁用的 `sandboxlocal` 本地用户；`sandbox-local setup windows` 显式检查/创建账户、batch logon right、Task Scheduler、Firewall 和 OpenSSH 状态；运行时通过 per-user firewall 和 host proxy 实现 offline/allowlist。
- 风险：Windows arm64/UTM 中备用凭据直启路径不稳定。
  缓解方式：已确认 `LogonUser/CreateProcessWithTokenW` 与 PowerShell `Start-Process -Credential` 会触发 `0xC0000142`；当前 Windows runner 改为一次性 Scheduled Task 路线，不再把直启路径作为闭环。
- 风险：路径、symlink、junction、glob、IP canonicalization 可能造成绕过。
  缓解方式：优先建设安全回归测试和 golden test。

## 里程碑

1. 初始化 Go module、Cobra CLI、SDK facade、policy model、noop backend、CLI smoke test。
2. 实现 macOS Seatbelt 后端，覆盖 filesystem、offline network、allowlist proxy。
3. 实现 Linux bubblewrap 后端，先覆盖 filesystem 和 offline network，再补 managed proxy 与 seccomp。
4. 实现 Windows local-user 后端，覆盖 ACL、firewall、scheduled task runner，再评估显式 setup helper。
5. 补齐三平台 CI、release artifact、SBOM、provenance 和 E2E。

## 验证方式

- 命令：
  - `go test ./...`
  - `go test -tags integration ./...`
  - `sandbox-local doctor --json`
  - `sandbox-local run --policy configs/examples/default.yaml -- <command>`
- 手工检查：
  - macOS 验证敏感路径读写拒绝和 allowlist 网络。
  - Linux 验证 bwrap mount plan、network namespace、proxy bridge。
  - Windows 验证 local-user sandbox identity、ACL、firewall、scheduled task cleanup。
- 观测检查：
  - SDK event 和 CLI `--json` 输出包含 backend、capability、denial、exit status。

## 验证记录

- 2026-04-21 macOS：
  - `make ci`
  - `go build -o ./bin/sandbox-local ./cmd/sandbox-local`
  - `./bin/sandbox-local doctor`
  - `./bin/sandbox-local run -- /bin/echo hello`
  - `./bin/sandbox-local run -- /bin/sh -c 'printf ok > sandbox-test-ok.txt'`
  - `./bin/sandbox-local run -- /bin/sh -c 'printf bad > .git/sandbox-test-denied'`，确认被 Seatbelt 拒绝。
  - `./bin/sandbox-local run -- /usr/bin/curl -I --max-time 5 https://example.com`，确认默认 offline 阻断。
  - `./bin/sandbox-local run --network open -- /usr/bin/curl -I --max-time 5 https://example.com`，确认 open 网络可用。
  - `./bin/sandbox-local run --network allowlist --allow-net example.com -- /usr/bin/curl -I --max-time 8 https://example.com`，确认 allowlist 允许。
  - `./bin/sandbox-local run --network allowlist --allow-net example.com -- /usr/bin/curl -I --max-time 8 https://openai.com`，确认 allowlist 拒绝。
- 2026-04-21 Linux：
  - `orb -m sandbox-local-linux go test ./...`
  - `orb -m sandbox-local-linux go build -o ./bin/sandbox-local-linux ./cmd/sandbox-local`
  - `orb -m sandbox-local-linux ./bin/sandbox-local-linux doctor`
  - `orb -m sandbox-local-linux ./bin/sandbox-local-linux run -- /bin/echo hello-linux`
  - `orb -m sandbox-local-linux ./bin/sandbox-local-linux run -- /bin/sh -c 'printf bad > .git/sandbox-linux-denied'`，确认被 bubblewrap 只读挂载拒绝。
  - `orb -m sandbox-local-linux ./bin/sandbox-local-linux run -- /usr/bin/curl -I --max-time 5 https://example.com`，确认默认 offline 阻断。
  - `orb -m sandbox-local-linux ./bin/sandbox-local-linux run --network open -- /usr/bin/curl -I --max-time 5 https://example.com`，确认 open 网络可用。
  - `orb -m sandbox-local-linux ./bin/sandbox-local-linux run --network allowlist --allow-net example.com -- /usr/bin/curl -I --max-time 8 https://example.com`，确认 allowlist 允许。
  - `orb -m sandbox-local-linux ./bin/sandbox-local-linux run --network allowlist --allow-net example.com -- /usr/bin/python3 -c 'import socket; socket.socket(socket.AF_UNIX)'`，确认 seccomp 阻断 AF_UNIX 绕过。
- 2026-04-21 Windows：
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && go test ./... && go build -o bin\sandbox-local.exe .\cmd\sandbox-local'`
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe doctor'`，确认 `windows-local-user` backend available，支持 `offline, open`，并显式提示 allowlist 未支持。
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe --backend noop run -- cmd /c echo hello-windows'`
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe policy init sandbox-local.yaml && bin\sandbox-local.exe policy validate sandbox-local.yaml'`
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe run --network open -- cmd.exe /c write-ok.bat && type win-ok.txt'`，确认 cwd 可写。
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe run --network open -- cmd.exe /c write-denied.bat'`，确认 `.git` 写入被 ACL 拒绝，且文件不存在。
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe run --network open --deny-read secret -- cmd.exe /c read-secret.bat'`，确认 read deny 生效。
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe run --network open -- curl.exe -I --max-time 8 https://example.com'`，确认 open 网络可用。
  - `ssh Leo@192.168.64.3 'cd /d C:\Users\Leo\sandbox-local-agent && bin\sandbox-local.exe run -- curl.exe -I --max-time 8 https://example.com'`，确认默认 offline 被 per-user firewall 阻断。
  - `ssh Leo@192.168.64.3 'net user | findstr /I sbx'` 与 `Get-NetFirewallRule -DisplayName 'sandbox-local-*'`，确认临时用户和防火墙规则清理干净。
  - 后续补丁新增临时用户 profile 目录清理、机器级 mutex `ERROR_ALREADY_EXISTS` 处理、请求 env JSON 转发，并把 runner 从手写环境块调整为 `LogonUserW` + `CreateEnvironmentBlock` + `CreateProcessWithTokenW`。
  - UTM Windows SSH 恢复后复验：`go test ./...`、Windows build、`doctor` 均通过；cleanup 检查显示无残留 `sbx*` 用户/profile 与 `sandbox-local-*` firewall rule。
  - 阻塞：最终复验中 `cmd.exe`、`whoami.exe`、`where.exe`、`powershell.exe` 在备用凭据路径下反复返回 `0xC0000142`。已排除/验证路径包括 `CreateProcessWithTokenW`、`LOGON_WITH_PROFILE`/profileless、Job Object on/off、PowerShell `Start-Process -Credential` 对照、batch logon token、OpenSSH 临时用户尝试；该问题当前限定在 Windows 进程启动兼容性，不能标记 Windows E2E 完备。
- 2026-04-22 Windows：
  - SSH 恢复后确认远端 `WIN-VT2FGSOBO07\Leo`、Windows `10.0.26100.8246`、OpenSSH Server running、管理员令牌可用。
  - 复现真实 Windows 后端 `cmd.exe` 仍返回 `0xC0000142`；对照验证 PowerShell `Start-Process -Credential` 同样返回 `-1073741502`。
  - 改为持久禁用账户 `sandboxlocal` + `SeBatchLogonRight` + 一次性 Scheduled Task runner，避开 `CreateProcessWithTokenW` 直启路径。
  - `ssh Leo@192.168.64.3 "cd /d C:\Users\Leo\sandbox-local-agent && sandbox-local.exe run --network open -- cmd.exe /c echo final-windows-smoke"`，确认真实后端可运行。
  - 验证 `--deny-read secret.txt` 返回 Access is denied；验证 `.git` 写入被拒绝；验证 `--network open` 可访问 `https://example.com`；验证默认 offline 阻断 `curl.exe`。
  - cleanup 检查确认无 `sandbox-local-*` scheduled task 和 firewall rule；`sandboxlocal` 账号保留但处于 disabled。此前调试临时用户留下的 loaded `sbx*` profile 需要重启 Windows 后再清理，当前实现不会继续创建新的 `sbx*` 用户。
- 2026-04-22 三端 SDK E2E：
  - macOS：`make ci`、`./scripts/e2e-sdk.sh`、`go test -tags integration ./tests/e2e` 通过。SDK integration 构建 helper binary 后验证 cwd 写 allow、`.git` 写 deny、`secret.txt` 读 deny、默认 offline 阻断、allowlist 允许 `example.com`、拒绝 `openai.com`、`curl --noproxy '*'` 直连绕过被阻断。
  - Linux：`orb -m sandbox-local-linux go test ./...`、`orb -m sandbox-local-linux go test -tags integration ./tests/e2e` 通过。修正 SDK 场景下 Linux allowlist helper 不能假设 `os.Executable()` 是 CLI 的问题，并让 seccomp exec wrapper 对命令名执行 PATH lookup。
  - Windows：重启后 SSH 恢复，清理旧 `sbx*` profile；`go test ./...`、`go build -o bin\sandbox-local.exe .\cmd\sandbox-local`、`bin\sandbox-local.exe setup windows`、`go test -tags integration ./tests/e2e` 通过。额外手工验证 `doctor` 暴露 `offline, allowlist, open`，allowlist 允许 `example.com`，非 allowlisted `openai.com` 返回 proxy 403，`--noproxy` 直连返回连接失败；cleanup 后无 `sandbox-local-*` scheduled task/firewall，`sandboxlocal` 保持 disabled。
- 2026-04-21 release：
  - `VERSION=0.1.0-test ./scripts/release-package.sh`
  - `jq . dist/release-manifest.json`

## 进度记录

- [x] 2026-04-21：完成参考仓库调研和初始架构设计。
- [x] 2026-04-21：确认 macOS 本机可用于开发与验证，`go1.26.1 darwin/arm64` 可用。
- [x] 2026-04-21：准备 Linux 验证环境。`multipass` 不可用，UTM 当前只有 Windows VM；已用本机 OrbStack CLI 创建 `sandbox-local-linux`，Ubuntu 25.10 arm64，`go1.24.4 linux/arm64` 与 `bubblewrap 0.11.0` 可用。
- [x] 2026-04-21：准备 Windows 验证环境。SSH `Leo@192.168.64.3` 可达，远端为 Windows arm64；已通过 `winget` 安装 `go1.26.2 windows/arm64`。
- [x] 2026-04-21：切换仓库许可到 Apache-2.0，并同步文档说明。
- [x] 2026-04-21：初始化 Go module 和 CLI/SDK 骨架，包含 `run`、`doctor`、`policy init/validate`、`debug plan`。
- [x] 2026-04-21：完成第一个可运行 noop backend smoke path，并补 SDK noop 单元测试。
- [x] 2026-04-21：完成 macOS 后端最小闭环：Seatbelt 文件写保护、offline/open 网络模式、CLI smoke。
- [x] 2026-04-21：完成 Linux 后端最小闭环：bubblewrap 文件写保护、offline/open 网络模式、CLI smoke。
- [x] 2026-04-21：实现 host-managed HTTP/HTTPS allowlist proxy，并先接入 macOS 强 enforcement。
- [x] 2026-04-21：实现 Linux allowlist 的 UDS proxy bridge 和 seccomp exec wrapper；验证允许域、拒绝域和 AF_UNIX socket 阻断。
- [x] 2026-04-21：完成 Windows 后端最小闭环：临时本地用户、ACL read/write 策略、offline/open 网络模式；2026-04-22 已替换为持久 `sandboxlocal` + scheduled task runner。
- [x] 2026-04-21：复验 Windows 临时用户/profile/firewall cleanup；确认 cleanup 正常。
- [x] 2026-04-22：解决 UTM Windows arm64 中备用凭据启动 `cmd.exe` / `whoami.exe` / `powershell.exe` 返回 `0xC0000142` 的兼容性问题；Windows runner 改走一次性 Scheduled Task。
- [x] 2026-04-22：补 `sandbox-local setup windows` 和 SDK `Manager.Setup`，显式检查 Windows sandbox identity 与系统能力。
- [x] 2026-04-22：实现 Windows allowlist 网络：host-managed HTTP/HTTPS proxy + per-user outbound firewall，验证允许域、拒绝域和 `--noproxy` 直连绕过阻断。
- [x] 2026-04-22：新增 `tests/e2e` SDK integration 和 `scripts/e2e-sdk.{sh,ps1}`，三端通过同一 SDK 调用链路验证文件和网络隔离。
- [x] 2026-04-22：补 helper binary resolution，SDK 上层应用可通过 `Options.HelperPath` / `SANDBOX_LOCAL_HELPER` 指向 `sandbox-local` helper，避免 Linux bridge / Windows runner 误执行业务进程。
- [x] 2026-04-21：完成三平台基础验证。macOS/Linux 跑真实 sandbox CLI；Windows 跑 `go test ./...`、build、doctor、policy 和 noop run。
- [x] 2026-04-21：完成 release 接入，把 `scripts/release-package.sh` 从模板元数据包替换为真实二进制产物。

## 后续增强

- [ ] 把 `go test -tags integration ./tests/e2e` 接入真实三平台 CI runner；Windows runner 需要管理员权限和可用 Task Scheduler/Firewall。
- [ ] 继续补 junction、glob、IP canonicalization、localhost/loopback 细分策略的安全回归；如需要隔离 Windows loopback 本地服务，再评估 WFP filter。
- [ ] 补 SBOM/provenance 和安装脚本，把 helper binary 分发约定写入 release 文档。

## 决策记录

- 2026-04-21：采用 OS-native sandbox 作为主路线；Docker 只作为外层环境或未来可选执行后端。
- 2026-04-21：`pkg/sandbox` 作为唯一稳定 SDK facade，`cmd/sandbox-local` 与上层应用都复用它。
- 2026-04-21：平台实现全部放入 `internal/backend/*`，通过统一 backend 接口隐藏 OS 细节。
- 2026-04-21：默认要求强制执行策略；无法保证 enforcement 时必须显式失败或记录降级。
- 2026-04-21：第一轮实现先支持 macOS/Linux 的 `offline` 与 `open` 网络模式；domain allowlist 需要 host-managed proxy，暂不静默伪实现。
- 2026-04-21：macOS/Linux allowlist 改为强 enforcement：macOS 只放行本地代理端口；Linux 使用 bwrap network namespace、loopback bridge、Unix socket host proxy 和 seccomp wrapper。
- 2026-04-21：Windows 第一轮采用临时本地用户作为 sandbox identity，运行时创建并清理用户、ACL 和 firewall rule；用机器级 mutex 串行化 ACL setup / cleanup，避免并发运行互相恢复旧 DACL。
- 2026-04-21：Windows runner 保持 local-user/Job Object 路线，但当前 UTM Windows arm64 的备用凭据启动路径不稳定；在找到稳定 helper 前，不把 Windows E2E 计为完备。
- 2026-04-22：Windows runner 改为持久禁用 `sandboxlocal` identity + 一次性 Scheduled Task；不再使用 `CreateProcessWithTokenW` 直启目标命令。该方案会保留一个 disabled 本地账户和 profile，换取稳定启动与避免 per-run profile 泄漏。
- 2026-04-22：SDK 场景不再假设当前进程就是 CLI；Linux allowlist bridge 和 Windows runner 统一通过 helper binary resolution 进入 internal command。CLI 自身默认使用当前 binary，上层 SDK 应传 `Options.HelperPath` 或设置 `SANDBOX_LOCAL_HELPER`。
- 2026-04-22：Windows allowlist 采用 host-managed proxy + per-user firewall，而不是静默代理环境变量。代理负责域名策略，firewall 阻断直连绕过；loopback 保留给 managed proxy，并在 `doctor` 中作为平台差异提示。

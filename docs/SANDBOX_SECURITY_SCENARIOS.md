# Sandbox 安全场景手册

这份文档用真实 case 描述当前 `sandbox-local` 已能覆盖的安全场景。它面向两类读者：

- 人：快速判断某个平台当前能保护什么、怎么手工复验。
- Agent / CI：把每个 case 直接演化为 E2E，避免只靠聊天上下文理解安全边界。

每个 case 都应该能映射到 CLI 或 SDK 调用。当前仓库里的 SDK 版本见 `tests/e2e/sdk_enforcement_test.go`，可通过 `go test -tags integration ./tests/e2e` 或 `scripts/e2e-sdk.{sh,ps1}` 运行。

## 通用约定

- 所有命令默认在仓库根目录执行。
- `sandbox-local` 默认网络模式是 `offline`。
- 默认文件策略允许当前工作目录读写，并拒绝写入 `.git`、`.codex`、`.agents`。
- 需要验证网络的 case 依赖本机可用 `curl`，Windows 使用 `curl.exe`。
- `allowlist` 的通过条件不是“能联网”，而是“只允许列入 allowlist 的目标，且直连绕过失败”。
- 如果平台 capability 不支持某个能力，`doctor` 或 `manager.Check` 必须显式暴露，不能静默降级为成功。

建议 E2E 断言统一包含：

```text
case_id
platform
backend
command
expected_exit_zero
stdout_or_stderr_contains
filesystem_artifact_exists
filesystem_artifact_absent
cleanup_assertion
```

## macOS

macOS 后端使用 `/usr/bin/sandbox-exec` 和动态生成的 Seatbelt profile。当前覆盖文件读写隔离、默认 offline 网络、allowlist 网络和直连绕过阻断。

### macOS 准备

```bash
go build -o ./bin/sandbox-local ./cmd/sandbox-local

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-local-macos.XXXXXX")"
mkdir -p "$WORKDIR/.git"
printf secret > "$WORKDIR/secret.txt"
```

### macOS-01：后端能力可见

目标：确认当前机器不是 noop，也不是静默 best-effort。

```bash
./bin/sandbox-local doctor --json
```

通过标准：

- `backend` 是 `macos-seatbelt`。
- `available` 是 `true`。
- `sandboxed` 是 `true`。
- `network_modes` 包含 `offline`、`allowlist`、`open`。

E2E 断言：解析 JSON，不依赖自然语言输出。

### macOS-02：允许写入工作目录

目标：上层应用可以让任务在 sandbox 工作目录内正常产出文件。

```bash
./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network open \
  -- /bin/sh -c 'printf ok > allowed.txt'

test "$(cat "$WORKDIR/allowed.txt")" = "ok"
```

通过标准：

- `run` 退出码为 `0`。
- `$WORKDIR/allowed.txt` 存在且内容是 `ok`。

E2E 断言：执行结果成功，并读取产物内容。

### macOS-03：拒绝写入 `.git`

目标：阻止任务篡改仓库元数据、hook 或历史对象。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network open \
  -- /bin/sh -c 'printf bad > .git/blocked.txt'; then
  echo "unexpected success"
  exit 1
fi

test ! -e "$WORKDIR/.git/blocked.txt"
```

通过标准：

- `run` 退出码非 `0`。
- `$WORKDIR/.git/blocked.txt` 不存在。

E2E 断言：失败应来自目标进程的访问拒绝，不应是 sandbox runner 崩溃。

### macOS-04：拒绝读取敏感文件

目标：即使文件在工作目录内，也能用显式 `deny-read` 阻止读取。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network open \
  --deny-read secret.txt \
  -- /bin/sh -c 'cat secret.txt >/dev/null'; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `run` 退出码非 `0`。
- stderr/stdout 中可出现系统级 permission denied，但不要求固定文案。

E2E 断言：目标进程失败，且不泄漏 `secret.txt` 内容。

### macOS-05：默认 offline 阻断外部网络

目标：默认策略下任务不能直接访问公网。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  -- /usr/bin/curl --fail -I --max-time 8 https://example.com; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `run` 退出码非 `0`。
- 不应返回 `HTTP/` 响应头。

E2E 断言：默认 policy 即 offline，不需要额外 flag。

### macOS-06：allowlist 只允许指定域名

目标：允许 `example.com`，拒绝未列入的目标。

```bash
./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network allowlist \
  --allow-net example.com \
  -- /usr/bin/curl --fail -I --max-time 8 https://example.com

if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network allowlist \
  --allow-net example.com \
  -- /usr/bin/curl --fail -I --max-time 8 https://openai.com; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `example.com` 请求退出码为 `0`。
- `openai.com` 请求退出码非 `0`。

E2E 断言：允许和拒绝必须在同一个 policy 形态下验证。

### macOS-07：拒绝 `--noproxy` 直连绕过

目标：任务不能跳过 managed proxy 直接访问 allowlisted 域名。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network allowlist \
  --allow-net example.com \
  -- /usr/bin/curl --fail --noproxy '*' -I --max-time 8 https://example.com; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `run` 退出码非 `0`。
- 不能拿到 `https://example.com` 的真实响应。

E2E 断言：验证的是直连绕过失败，不是域名拒绝。

## Linux

Linux 后端使用 bubblewrap / namespaces。`allowlist` 使用 sandbox 内 loopback bridge、host Unix socket proxy 和 seccomp exec wrapper，目标是既能代理允许的域名，又阻断直接 socket 绕过。

### Linux 准备

```bash
go build -o ./bin/sandbox-local ./cmd/sandbox-local

WORKDIR="$(mktemp -d /tmp/sandbox-local-linux.XXXXXX)"
mkdir -p "$WORKDIR/.git"
printf secret > "$WORKDIR/secret.txt"
```

### Linux-01：后端能力可见

目标：确认当前机器具备 bubblewrap sandbox 能力。

```bash
./bin/sandbox-local doctor --json
```

通过标准：

- `backend` 是 `linux-bubblewrap`。
- `available` 是 `true`。
- `sandboxed` 是 `true`。
- `network_modes` 包含 `offline`、`allowlist`、`open`。

E2E 断言：如果 CI runner 缺少 user namespace 或 `bwrap`，应明确 skip/fail，不要误判为通过。

### Linux-02：允许写入工作目录

目标：任务可在工作目录内产出文件。

```bash
./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network open \
  -- /bin/sh -c 'printf ok > allowed.txt'

test "$(cat "$WORKDIR/allowed.txt")" = "ok"
```

通过标准：

- `run` 退出码为 `0`。
- `$WORKDIR/allowed.txt` 存在且内容是 `ok`。

E2E 断言：产物由 sandbox 内进程创建，而不是测试代码预创建。

### Linux-03：拒绝写入 `.git`

目标：通过只读挂载或 deny remount/mask 阻止写仓库元数据。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network open \
  -- /bin/sh -c 'printf bad > .git/blocked.txt'; then
  echo "unexpected success"
  exit 1
fi

test ! -e "$WORKDIR/.git/blocked.txt"
```

通过标准：

- `run` 退出码非 `0`。
- `$WORKDIR/.git/blocked.txt` 不存在。

E2E 断言：既检查 exit code，也检查 host 文件系统没有副作用。

### Linux-04：拒绝读取敏感文件

目标：显式 deny-read 的文件不可被 sandbox 内进程读取。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network open \
  --deny-read secret.txt \
  -- /bin/sh -c 'cat secret.txt >/dev/null'; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `run` 退出码非 `0`。
- 不泄漏 `secret.txt` 内容。

E2E 断言：deny-read 对工作目录内路径也生效。

### Linux-05：默认 offline 阻断外部网络

目标：默认 policy 下没有外部网络。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  -- curl --fail -I --max-time 8 https://example.com; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `run` 退出码非 `0`。
- 不返回公网 HTTP 响应。

E2E 断言：offline 是默认值。

### Linux-06：allowlist 只允许指定域名

目标：代理路径允许 `example.com`，拒绝未列入域名。

```bash
./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network allowlist \
  --allow-net example.com \
  -- curl --fail -I --max-time 8 https://example.com

if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network allowlist \
  --allow-net example.com \
  -- curl --fail -I --max-time 8 https://openai.com; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `example.com` 成功。
- `openai.com` 失败。

E2E 断言：失败应来自 allowlist 拒绝或网络不可达，不能使用 `open` 网络代替。

### Linux-07：拒绝 `--noproxy` 直连绕过

目标：任务不能跳过 managed proxy 直接连公网。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network allowlist \
  --allow-net example.com \
  -- curl --fail --noproxy '*' -I --max-time 8 https://example.com; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `run` 退出码非 `0`。
- 不能拿到 `example.com` 的真实响应。

E2E 断言：这个 case 用于证明 allowlist 不只依赖应用自觉使用 proxy。

### Linux-08：拒绝 AF_UNIX/socket 绕过

目标：阻断 sandbox 内进程创建可绕过 bridge 的本地 socket 通道。

```bash
if ./bin/sandbox-local run \
  --cwd "$WORKDIR" \
  --network allowlist \
  --allow-net example.com \
  -- /usr/bin/python3 -c 'import socket; socket.socket(socket.AF_UNIX)'; then
  echo "unexpected success"
  exit 1
fi
```

通过标准：

- `run` 退出码非 `0`。
- 如果 runner 缺少 `/usr/bin/python3`，E2E 应 skip 并说明依赖缺失。

E2E 断言：这是 Linux 特有的 seccomp/bridge 绕过回归。

## Windows

Windows 后端使用持久但默认禁用的本地用户 `sandboxlocal`、文件 ACL/DACL、一次性 Scheduled Task runner 和 per-user Firewall。`allowlist` 通过 host-managed HTTP/HTTPS proxy 执行域名允许/拒绝，并用 per-user outbound firewall 阻断直连绕过。loopback 当前保留给 managed proxy。

### Windows 准备

在管理员 PowerShell 中执行：

```powershell
go build -o .\bin\sandbox-local.exe .\cmd\sandbox-local

$WorkDir = Join-Path $env:TEMP ("sandbox-local-windows-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force (Join-Path $WorkDir ".git") | Out-Null
Set-Content -NoNewline -Path (Join-Path $WorkDir "secret.txt") -Value "secret"

.\bin\sandbox-local.exe setup windows
```

### Windows-01：后端能力可见

目标：确认 Windows 真实后端可用，并暴露 allowlist 能力。

```powershell
.\bin\sandbox-local.exe doctor --json
```

通过标准：

- `backend` 是 `windows-local-user`。
- `available` 是 `true`。
- `sandboxed` 是 `true`。
- `network_modes` 包含 `offline`、`allowlist`、`open`。
- 输出 warning 提示 Windows allowlist 使用 host-managed proxy 和 per-user firewall，loopback 保留给 managed proxy。

E2E 断言：解析 JSON 校验字段；warning 可作为文本快照，但不要依赖完整句子。

### Windows-02：setup 后 sandbox identity 保持禁用

目标：预创建或修复 sandbox identity 后，不让该账户常驻启用。

```powershell
.\bin\sandbox-local.exe setup windows
(Get-LocalUser sandboxlocal).Enabled
```

通过标准：

- `setup` 退出码为 `0`。
- `sandboxlocal` 的 `Enabled` 是 `False`。

E2E 断言：setup 是幂等的；重复执行不应留下 enabled 账户。

### Windows-03：允许写入工作目录

目标：sandbox 内进程可以在工作目录正常产出文件。

```powershell
.\bin\sandbox-local.exe run `
  --cwd $WorkDir `
  --network open `
  -- cmd.exe /c "echo ok>allowed.txt"

if ((Get-Content (Join-Path $WorkDir "allowed.txt")).Trim() -ne "ok") {
  throw "allowed write did not create expected content"
}
```

通过标准：

- `run` 退出码为 `0`。
- `$WorkDir\allowed.txt` 存在且内容是 `ok`。

E2E 断言：产物由 `sandboxlocal` 运行的任务创建。

### Windows-04：拒绝写入 `.git`

目标：ACL/DACL 阻止 sandbox identity 写入仓库元数据。

```powershell
.\bin\sandbox-local.exe run `
  --cwd $WorkDir `
  --network open `
  -- cmd.exe /c "echo bad>.git\blocked.txt"

if ($LASTEXITCODE -eq 0) {
  throw "unexpected success"
}
if (Test-Path (Join-Path $WorkDir ".git\blocked.txt")) {
  throw "blocked file was created"
}
```

通过标准：

- `run` 退出码非 `0`。
- `$WorkDir\.git\blocked.txt` 不存在。

E2E 断言：同时验证退出码和 host 文件系统副作用。

### Windows-05：拒绝读取敏感文件

目标：显式 deny-read 的文件不能被 sandbox identity 读取。

```powershell
.\bin\sandbox-local.exe run `
  --cwd $WorkDir `
  --network open `
  --deny-read secret.txt `
  -- cmd.exe /c "type secret.txt >NUL"

if ($LASTEXITCODE -eq 0) {
  throw "unexpected success"
}
```

通过标准：

- `run` 退出码非 `0`。
- 输出里不包含 `secret`。

E2E 断言：deny-read 不能因为文件位于工作目录而被 write/read allow 覆盖。

### Windows-06：默认 offline 阻断外部网络

目标：默认策略下阻止 `sandboxlocal` 出站访问公网。

```powershell
.\bin\sandbox-local.exe run `
  --cwd $WorkDir `
  -- curl.exe --fail -I --max-time 8 https://example.com

if ($LASTEXITCODE -eq 0) {
  throw "unexpected success"
}
```

通过标准：

- `run` 退出码非 `0`。
- 不返回公网 HTTP 响应。

E2E 断言：默认 offline 依赖 per-user firewall，不能只检查环境变量。

### Windows-07：allowlist 只允许指定域名

目标：允许 `example.com`，拒绝未列入的目标。

```powershell
.\bin\sandbox-local.exe run `
  --cwd $WorkDir `
  --network allowlist `
  --allow-net example.com `
  -- curl.exe --fail -I --max-time 8 https://example.com

if ($LASTEXITCODE -ne 0) {
  throw "allowlisted request failed"
}

.\bin\sandbox-local.exe run `
  --cwd $WorkDir `
  --network allowlist `
  --allow-net example.com `
  -- curl.exe --fail -I --max-time 8 https://openai.com

if ($LASTEXITCODE -eq 0) {
  throw "unexpected success"
}
```

通过标准：

- `example.com` 成功。
- `openai.com` 失败，通常表现为 proxy deny 或 HTTP failure。

E2E 断言：成功和失败必须使用同一个 allowlist policy。

### Windows-08：拒绝 `--noproxy` 直连绕过

目标：任务不能跳过 managed proxy 直连外部网络。

```powershell
.\bin\sandbox-local.exe run `
  --cwd $WorkDir `
  --network allowlist `
  --allow-net example.com `
  -- curl.exe --fail --noproxy '*' -I --max-time 8 https://example.com

if ($LASTEXITCODE -eq 0) {
  throw "unexpected success"
}
```

通过标准：

- `run` 退出码非 `0`。
- 不能拿到 `example.com` 的真实响应。

E2E 断言：这个 case 证明 per-user firewall 阻断了绕过 proxy 的外部直连。

### Windows-09：运行后 cleanup 无残留

目标：每次 run 后不留下 scheduled task、防火墙规则或启用的 sandbox 账户。

```powershell
$Tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "sandbox-local-*" }
$Rules = Get-NetFirewallRule -DisplayName "sandbox-local-*" -ErrorAction SilentlyContinue
$UserEnabled = (Get-LocalUser sandboxlocal).Enabled

if ($Tasks) {
  throw "sandbox-local scheduled task leaked"
}
if ($Rules) {
  throw "sandbox-local firewall rule leaked"
}
if ($UserEnabled) {
  throw "sandboxlocal should be disabled after cleanup"
}
```

通过标准：

- 无 `sandbox-local-*` scheduled task。
- 无 `sandbox-local-*` firewall rule。
- `sandboxlocal` 账户存在但 `Enabled` 是 `False`。

E2E 断言：cleanup 失败应被视为安全失败，而不是测试警告。

## 当前覆盖矩阵

| 场景 | macOS | Linux | Windows |
| --- | --- | --- | --- |
| 后端能力显式报告 | 是 | 是 | 是 |
| 工作目录允许写 | 是 | 是 | 是 |
| `.git` 写保护 | 是 | 是 | 是 |
| 显式 read deny | 是 | 是 | 是 |
| 默认 offline 网络 | 是 | 是 | 是 |
| allowlist 允许指定域名 | 是 | 是 | 是 |
| allowlist 拒绝未列入域名 | 是 | 是 | 是 |
| `--noproxy` 直连绕过阻断 | 是 | 是 | 是 |
| socket 绕过专项回归 | 不适用 | AF_UNIX/socketpair | 不适用 |
| Windows identity / task / firewall cleanup | 不适用 | 不适用 | 是 |

## 可演化为 E2E 的最小集合

优先把这些 case 固化进三端 CI：

1. `doctor` 能力报告。
2. 工作目录 allowed write。
3. `.git` denied write，并检查文件不存在。
4. `deny-read secret.txt`，并检查 secret 不泄漏。
5. 默认 offline 阻断 `curl https://example.com`。
6. allowlist 允许 `example.com`。
7. allowlist 拒绝 `openai.com`。
8. allowlist 下 `curl --noproxy '*' https://example.com` 失败。
9. Windows cleanup 检查 scheduled task、firewall rule、`sandboxlocal.Enabled`。
10. Linux AF_UNIX/socketpair 绕过检查。

这些 case 的 SDK 形态应该使用同一个上层调用链路：上层应用构建或发现 `sandbox-local` helper binary，通过 `sandbox.NewManager(sandbox.Options{HelperPath: helperPath})` 创建 manager，先 `Setup`，再 `Run`。

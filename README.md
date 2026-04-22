# sandbox-local

跨平台本地 sandbox runtime，面向 Agent 和上层客户端应用。

它提供两种入口，但走同一套策略和后端：

- Go SDK：`pkg/sandbox`
- CLI：`sandbox-local`

默认不把 Docker 当作 sandbox 后端，而是封装各主流 OS 的原生隔离能力。

## 三端能力

| 平台 | 后端 | 当前覆盖 |
| --- | --- | --- |
| macOS | Seatbelt / `sandbox-exec` | 文件读写策略，`offline` / `allowlist` / `open` 网络 |
| Linux | bubblewrap、namespaces、seccomp bridge | 文件策略、network namespace、allowlist proxy、直连 socket 绕过阻断 |
| Windows | disabled local user、ACL、Scheduled Task runner、Firewall | 文件 ACL 策略、`setup windows`、`offline` / `allowlist` / `open` 网络、cleanup |

## 快速开始

构建 CLI：

```bash
go build -o ./bin/sandbox-local ./cmd/sandbox-local
```

查看当前后端能力：

```bash
./bin/sandbox-local doctor --json
```

用默认策略跑一个命令：

```bash
./bin/sandbox-local run -- /bin/echo hello
```

默认策略：

- 网络是 `offline`
- 当前目录可读写
- `.git`、`.codex`、`.agents` 禁止写入
- `~/.ssh`、`~/.aws` 等常见敏感目录禁止读取

## CLI 示例

允许命令写入当前目录：

```bash
./bin/sandbox-local run -- /bin/sh -c 'printf ok > allowed.txt'
```

阻止写入 `.git`：

```bash
./bin/sandbox-local run -- /bin/sh -c 'printf bad > .git/blocked.txt'
```

只允许访问 `example.com`：

```bash
./bin/sandbox-local run \
  --network allowlist \
  --allow-net example.com \
  -- curl --fail -I --max-time 8 https://example.com
```

Windows 先准备宿主机能力：

```powershell
.\bin\sandbox-local.exe setup windows
.\bin\sandbox-local.exe doctor --json
```

## Go SDK

最小调用形态：

```go
manager, err := sandbox.NewManager(sandbox.Options{
	HelperPath: "./bin/sandbox-local",
})
if err != nil {
	return err
}
defer manager.Close()

if _, err := manager.Setup(ctx, sandbox.SetupRequest{TargetPlatform: runtime.GOOS}); err != nil {
	return err
}

result, err := manager.Run(ctx, sandbox.Request{
	Command: []string{"/bin/sh", "-c", "printf ok > allowed.txt"},
	Cwd:     workdir,
	Policy: sandbox.Policy{
		Filesystem: sandbox.FilesystemPolicy{
			ReadAllow:  []string{workdir},
			ReadDeny:   []string{filepath.Join(workdir, "secret.txt")},
			WriteAllow: []string{workdir},
			WriteDeny:  []string{filepath.Join(workdir, ".git")},
		},
		Network: sandbox.NetworkPolicy{
			Mode: sandbox.NetworkOffline,
		},
		Process: sandbox.ProcessPolicy{
			Timeout: 20 * time.Second,
		},
	},
})
if err != nil {
	return err
}
_ = result.ExitCode
```

SDK 上层应用应设置 `Options.HelperPath` 或 `SANDBOX_LOCAL_HELPER`，指向 `sandbox-local` helper binary。这样 Linux bridge / Windows runner 不会把上层业务进程误当作内部 helper 重新执行。

## 安全场景

实际能覆盖的安全 case 见：

- `docs/SANDBOX_SECURITY_SCENARIOS.md`

里面按 macOS、Linux、Windows 分节记录：

- 后端能力报告
- 工作目录允许写
- `.git` 写保护
- 敏感文件 read deny
- 默认 offline 网络
- allowlist 允许/拒绝域名
- `curl --noproxy '*'` 直连绕过阻断
- Linux AF_UNIX/socket 绕过回归
- Windows scheduled task、firewall rule、`sandboxlocal` cleanup

## 测试

单元测试：

```bash
go test ./...
```

仓库级检查：

```bash
make ci
```

SDK integration E2E：

```bash
go test -tags integration ./tests/e2e
```

或：

```bash
./scripts/e2e-sdk.sh
```

Windows：

```powershell
.\scripts\e2e-sdk.ps1
```

## 文档

- `docs/ARCHITECTURE.md`：顶层架构和平台边界
- `docs/design-docs/go-sandbox-runtime-architecture.md`：详细设计
- `docs/SANDBOX_SECURITY_SCENARIOS.md`：具体安全场景
- `docs/exec-plans/active/go-sandbox-runtime.md`：实现进度和后续增强

## License

[Apache-2.0](LICENSE)

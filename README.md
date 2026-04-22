# sandbox-local

English | [简体中文](README.zh-CN.md)

Cross-platform local sandbox runtime for agents and upper-level client applications.

It exposes the same policy and backend path through two entry points:

- Go SDK: `pkg/sandbox`
- CLI: `sandbox-local`

By default, `sandbox-local` wraps OS-native isolation instead of using Docker as the sandbox backend.

## Platform Coverage

| Platform | Backend | Current coverage |
| --- | --- | --- |
| macOS | Seatbelt / `sandbox-exec` | filesystem read/write policy, `offline` / `allowlist` / `open` networking |
| Linux | bubblewrap, namespaces, seccomp bridge | filesystem policy, network namespace, allowlist proxy, direct socket bypass blocking |
| Windows | disabled local user, ACL, Scheduled Task runner, Firewall | filesystem ACL policy, `setup windows`, `offline` / `allowlist` / `open` networking, cleanup |

## Quick Start

Build the CLI:

```bash
go build -o ./bin/sandbox-local ./cmd/sandbox-local
```

Check backend capability:

```bash
./bin/sandbox-local doctor --json
```

Run a command with the default policy:

```bash
./bin/sandbox-local run -- /bin/echo hello
```

Default policy:

- network mode is `offline`
- the current directory is readable and writable
- `.git`, `.codex`, and `.agents` are write-denied
- common sensitive locations such as `~/.ssh` and `~/.aws` are read-denied

## CLI Examples

Allow a command to write into the current directory:

```bash
./bin/sandbox-local run -- /bin/sh -c 'printf ok > allowed.txt'
```

Block writes to `.git`:

```bash
./bin/sandbox-local run -- /bin/sh -c 'printf bad > .git/blocked.txt'
```

Allow only `example.com`:

```bash
./bin/sandbox-local run \
  --network allowlist \
  --allow-net example.com \
  -- curl --fail -I --max-time 8 https://example.com
```

Prepare Windows host requirements:

```powershell
.\bin\sandbox-local.exe setup windows
.\bin\sandbox-local.exe doctor --json
```

## Go SDK

Minimal usage:

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

SDK callers should set `Options.HelperPath` or `SANDBOX_LOCAL_HELPER` to the `sandbox-local` helper binary. This prevents the Linux bridge or Windows runner from re-executing the upper application binary as an internal helper.

## Security Scenarios

Concrete safety cases are documented in:

- `docs/SANDBOX_SECURITY_SCENARIOS.md`

It contains macOS, Linux, and Windows sections for:

- backend capability reporting
- allowed workspace writes
- `.git` write protection
- sensitive file read deny
- default offline networking
- allowlist allow/deny domains
- `curl --noproxy '*'` direct bypass blocking
- Linux AF_UNIX/socket bypass regression
- Windows scheduled task, firewall rule, and `sandboxlocal` cleanup

## Testing

Unit tests:

```bash
go test ./...
```

Repository-level checks:

```bash
make ci
```

SDK integration E2E:

```bash
go test -tags integration ./tests/e2e
```

or:

```bash
./scripts/e2e-sdk.sh
```

Windows:

```powershell
.\scripts\e2e-sdk.ps1
```

## Docs

- `docs/ARCHITECTURE.md`: top-level architecture and platform boundaries
- `docs/design-docs/go-sandbox-runtime-architecture.md`: detailed design
- `docs/SANDBOX_SECURITY_SCENARIOS.md`: concrete security scenarios
- `docs/exec-plans/active/go-sandbox-runtime.md`: implementation progress and follow-up work

## License

[Apache-2.0](LICENSE)

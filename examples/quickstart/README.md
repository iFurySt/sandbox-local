# sandbox-local SDK quickstart

This example is a standalone Go module that imports the published
`github.com/iFurySt/sandbox-local/pkg/sandbox` package.

Run it from this directory:

```bash
go run .
```

The example uses its own executable as the sandbox helper:

```go
if sandbox.MaybeRunHelper() {
    return
}

manager, err := sandbox.NewManager(sandbox.Options{
    HelperPath: os.Args[0],
})
```

On Windows, ordinary users automatically use AppContainer without administrator
setup. Use an interactive user session for PowerShell and keep the executable
and dependencies in a user-owned directory or an installation readable by app
packages. `allowlist` requires the elevated backend; ordinary-user mode rejects
it. Elevated runs retain the local-runner backend and require administrator
privileges on every invocation.

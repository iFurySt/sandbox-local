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

On Windows, run from an elevated terminal the first time so the sandbox backend
can prepare the local sandbox identity, scheduled task, and firewall
prerequisites.

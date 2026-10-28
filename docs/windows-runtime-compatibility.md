# Windows runtime compatibility

Standard-user execution uses AppContainer. Its filesystem, network, desktop and
process-tree restrictions also apply to child processes; runtime compatibility
must be fixed without disabling those restrictions.

## Node child-process pipes

Node 22.23.2 can run scripts and children with inherited stdio, but capturing a
child's output hangs inside AppContainer. The failure is in libuv's creation of
child stdio and IPC pipes, before the child starts. AppContainer permits pipe
creation in `\\.\pipe\LOCAL\`; older libuv creates global pipe names and retries
access-denied failures indefinitely.

The upstream fix is [libuv #5181](https://github.com/libuv/libuv/pull/5181),
commit `2cadaa40167050baf7c6905ac897e6fb57afb2c6`. It detects `TokenIsAppContainer`
and adds `LOCAL` to generated pipe names only inside the container. This fixes
the runtime without changing the sandbox's security boundary.

As of 2026-10-28, Node's official 22, 24 and 26 release lines do not include this
fix; see [Node #66374](https://github.com/nodejs/node/issues/66374). Merely
upgrading between those release lines does not solve it. Full child-process
support requires a Node build containing that upstream change, or a later
release confirmed by a sandboxed regression test. The SDK does not rewrite,
inject code into, or silently replace caller-supplied executables.

Inside a sandbox with read access to Node, this reproduces the affected path:

```javascript
const { execFileSync } = require('node:child_process');
console.log(execFileSync(process.execPath, ['-e', 'console.log("child")'], {
  encoding: 'utf8',
}));
```

Using `stdio: 'inherit'` avoids captured pipes when the caller can forward
output directly. It is not a replacement for APIs that must inspect that output.
The native regression `TestAppContainerLocalNamedPipe` checks that the allowed
LOCAL namespace works; it does not certify an external Node distribution.

## PowerShell and installation paths

Windows PowerShell 5.1 can fail to resolve its filesystem provider if the volume
root is unreadable. A caller can mount its allowed workspace with `New-PSDrive`
and select that drive, without granting access to ancestor directories. The
physical path is available through `(Get-Location).ProviderPath`.

PowerShell and other USER32 workloads require an interactive user session;
service and SSH session 0 may fail DLL initialization. Executables and their
libraries must be AppContainer-readable. Neither limitation permits an
unrestricted fallback.

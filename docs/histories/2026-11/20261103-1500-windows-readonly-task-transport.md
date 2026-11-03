# Windows readonly task transport

## Request

Fix Windows readonly execution timeouts, add native execution and lifecycle regressions, then integrate the validated SDK into its consumer.

## Changes

- Move task control files outside the business CWD into a private, protected directory owned by host cleanup.
- Replace PowerShell task stdio redirection with a native broker, preserving binary input/output, Unicode paths and command exit codes.
- Prevent the restricted command from changing control files; report bootstrap failures without waiting for the command deadline.
- Make mutex queuing cancellable while preserving ownership on one OS thread; signal cancellation before killing the helper and reclaim the task's process tree with a Job Object.
- Add native readonly, quoting, stdin, output, exit-code, mutation-denial, cancellation and concurrent-execution coverage to Windows CI.

## Verification

Native test results and validation limits are recorded in the execution plan. The public API and standard-user AppContainer backend remain unchanged.

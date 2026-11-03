# Windows readonly task transport

## Goal

Fix readonly execution hangs and validate Windows command execution before integrating the SDK into its consumer. Preserve the existing filesystem/network enforcement and standard-user AppContainer behavior.

## Implementation

- Protected task directory outside the business CWD, with host-owned cleanup and a write denial for the command capability SID.
- Direct native broker action registered through UTF-16 task XML, binary stdin/stdout/stderr files and separate bootstrap/command completion reports.
- Job Object for the restricted command tree, cooperative helper cancellation with bounded forced termination, and cancellable setup-lock acquisition on its owner thread.
- Windows native regressions for readonly operations, control-file mutation, special paths/argv, binary stdin, dual output, exit codes, bootstrap errors, cancellation, descendants and concurrent/repeated execution.

## Progress

- [x] Localize released failure: readonly CWD's inherited write-deny ACL blocks task output and completion files; completed tasks then appear to time out. Reproduced three consecutive times and isolated with an ACL A/B control.
- [x] Implement private task transport and explicit failure handling.
- [x] Run local repository CI, Windows static checks and cross-compilation.
- [x] Finish native Windows matrix and repeated lifecycle validation.
- [ ] Create SDK PR, verify checks and merge after native validation.
- [ ] Update latest consumer release to merged SDK, validate the actual Executor and create its MR only after success.

## Evidence and limits

After merging the latest main, the Windows 10 x64 test host passed three complete matrix rounds: 57 SDK invocation attempts covering readonly commands, write denial, special paths/argv, binary stdin, dual-stream output, nonzero exit, bootstrap errors, cancellation, timeout, descendants, background handles and concurrent callers. Each lifecycle round audited new task/IPC residue. Setup-lock tests passed ten repetitions and transport/security tests passed three repetitions.

Tested helper SHA-256: `439f432f7190f2ba840033b9b25424d2113dce1164e33be667019acb4cd6d350`.
Test executable SHA-256: `1bd7d50f72758172f914ec124ea70597933878eb66070beec05dedad3f83594d`.
The code candidate is 97b15c4; later plan updates do not change product code. Normal foreground completion preserves late background stdout/stderr writers, while cancellation and timeout reap descendants. All three native matrix rounds verified this distinction.

The test-machine owner explicitly authorized a temporary Defender exclusion limited to its dedicated test directory; real-time protection remained enabled. Remove the exclusion after consumer testing. A separate GitHub Windows runner also passed the native tests without a task-created exclusion. GitHub run 41596635998 passed repository checks and the three-round native Windows matrix. Final PR checks must still pass before merge.

Local `make ci`, `go test -race ./...`, Windows amd64 vet and ARM64 build passed. Windows ARM64 compilation does not imply ARM64 runtime validation; the elevated SSH session does not cover an interactive standard-user AppContainer session. Consumer integration remains a separate follow-up after this SDK PR merges.

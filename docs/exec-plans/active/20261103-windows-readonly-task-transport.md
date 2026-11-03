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
- [ ] Finish native Windows matrix and repeated lifecycle validation.
- [ ] Create SDK PR, verify checks and merge after native validation.
- [ ] Update latest consumer release to merged SDK, validate the actual Executor and create its MR only after success.

## Evidence and limits

The initial private-directory candidate passed native control-file mutation tests three times and five readonly command cases. The native-broker candidate then passed special-path argv, binary stdin, simultaneous 100 KB stdout/stderr and exit-code checks. These earlier runs are evidence for their respective candidates, not a pass for the final branch.

Windows Defender subsequently blocked the self-built helper's scheduled-task behavior. Broader native tests and final-candidate verification remain pending; do not disable protection or add exclusions without test-machine-owner authorization. Record final artifact hashes, native results and unavailable coverage before merging. Local macOS race tests do not substitute for native Windows tests. Windows ARM64 compile checks do not imply ARM64 runtime validation, and the elevated SSH session does not cover an interactive standard-user AppContainer session.

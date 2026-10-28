# Windows standard-user sandbox

## Goal

Run the SDK without elevation or an administrator-installed service while preserving filesystem denials and offline networking.

## Implementation

- Select per-invocation AppContainer profiles for tokens without enabled administrator membership.
- Retain ordinary restricted-token checks for deny rules; isolate the desktop and contain the process tree in a Job Object.
- Remove only per-invocation ACL entries, preserving overlapping invocations.
- Reject unsupported allowlist networking; document loopback, interactive-session and executable-readability requirements.

## Status

Completed.

## Validation

Windows 10 amd64 native tests under an administrator-disabled token cover allowed operations, blocked reads/writes/deletion/rename/ACL changes, offline networking, nested-token attempts, descendant cancellation, and overlapping cleanup. macOS race tests also pass. The actual standard-account service-session probe confirms the documented USER32 initialization limitation; interactive execution is validated with administrator membership disabled. Base CI and Windows vet pass.

Compatibility follow-up: Windows 10 denies global named-pipe creation inside AppContainer, while LOCAL named pipes and inherited-stdio children work. Node child_process output capture through global pipes can time out; this limitation is reported explicitly.

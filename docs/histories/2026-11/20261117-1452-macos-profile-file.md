## [2026-11-17 14:52] | Task: Load macOS Seatbelt profiles from temporary files

### Execution Context

- **Agent ID**: Codex
- **Base Model**: GPT-6
- **Runtime**: Codex desktop

### User Query

Fix macOS sandbox startup failures when large filesystem policies exceed the
process argument limit, then validate the consuming application.

### Changes Overview

**Scope:** macOS backend, SDK regression tests and lifecycle documentation.

- Write each generated profile to a private temporary directory and pass its
  filename to `sandbox-exec -f`.
- Reuse backend cleanup for normal completion, nonzero exits, cancellation,
  timeouts and diagnostic preparation; reject temporary-file creation failures.
- Cover large profiles with real macOS execution and preserve denied writes.

### Design Intent

The profile previously occupied one command-line argument. Loading the same
policy from a file avoids the argument limit without changing its enforcement.
The profile file is owner-readable and owner-writable; its directory is private
to the current user. Existing cleanup ownership remains in the execution manager.

### Validation

- The large-profile regression fails with `argument list too long` before the
  backend change.
- Affected backend and SDK tests pass with the race detector on macOS.

### Files Modified

- `internal/backend/macos/backend.go`
- `internal/backend/macos/profile_file_test.go`
- `pkg/sandbox/profile_darwin_test.go`
- `docs/ARCHITECTURE.md`
- `docs/design-docs/go-sandbox-runtime-architecture.md`

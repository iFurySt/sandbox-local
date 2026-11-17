## [2026-11-17 19:54] | Task: inline macOS Seatbelt profile

### 📥 User Query

> Change the macOS backend to pass the full Seatbelt policy inline to `sandbox-exec`, without product-specific assumptions or temporary policy files.

### 🛠 Changes Overview

**Scope:** macOS backend and its native regressions.

- Pass the generated policy with `/usr/bin/sandbox-exec -p`.
- Remove temporary profile creation, writes, and cleanup.
- Cover inline policy construction, special-character paths, and native write-deny enforcement.

### 🧠 Design Intent (Why)

The calling integration requires the complete generated policy to be supplied inline. This removes temporary-file lifecycle handling while preserving Seatbelt filesystem and network policy generation. Policies remain bounded by the macOS process argument-size limit.

### 📁 Files Modified

- `internal/backend/macos/backend.go`
- `internal/backend/macos/profile_file_test.go`
- `pkg/sandbox/profile_darwin_test.go`
- `docs/ARCHITECTURE.md`
- `docs/design-docs/go-sandbox-runtime-architecture.md`
- `docs/releases/feature-release-notes.md`

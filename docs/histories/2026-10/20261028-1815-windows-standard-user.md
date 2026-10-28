## [2026-10-28 18:15] | Task: Support Windows standard users

### 🤖 Execution Context

- **Agent ID**: `/root`
- **Base Model**: GPT-6 (exact variant unavailable)
- **Runtime**: Codex desktop

### 📥 User Query

> Support sandbox execution for Windows users without administrator privileges.

### 🛠 Changes Overview

- Select a per-invocation AppContainer for tokens without enabled Administrators membership.
- Add restricted-token denials, scoped ACL cleanup, a private desktop, and Job Object process-tree cleanup.
- Keep the elevated local-user backend and reject unsupported standard-user network allowlists.
- Document executable readability, loopback and interactive-session requirements.

### 🧠 Design Intent (Why)

The local-account backend manages machine resources on every invocation, so one administrator setup cannot enable ordinary-user execution. Per-user AppContainer profiles provide an OS boundary without a privileged broker. Package-SID deny ACEs are insufficient; ordinary restricted-token checks enforce denials.

### 📁 Files Modified

- `internal/appcontainer/`
- `internal/backend/windows/appcontainer*.go`
- `internal/backend/windows/backend.go`
- `internal/engine/manager.go`
- `internal/helpercmd/helpercmd.go`
- README, architecture, security scenarios, quickstart and release notes

### Validation

- Windows 10 amd64 native tests with administrator membership disabled: file allow/deny, protected deletion/rename, ACL mutation, offline networking, nested-token attempts, descendant cancellation and overlapping cleanup.
- macOS `go test -race ./...`, `make ci`, Windows cross-compilation and `go vet`.
- A separate standard-account session-0 probe cannot initialize USER32; it is a documented unsupported execution context, not a passing desktop test.

Compatibility follow-up: Windows 10 denies global named-pipe creation inside AppContainer, while LOCAL named pipes and inherited-stdio children work. Node child_process output capture through global pipes can time out; this limitation is reported explicitly.

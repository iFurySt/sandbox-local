# Windows protected command overlap — 2026-11-23

## Problem and changes

Protected background commands must allow short commands in the same workspace to finish and expose output before termination, while retaining sandbox isolation.

- Use per-invocation accounts and capability SIDs, short ACL mutation locks and SID-specific rollback; retain exclusive restoration for null DACLs.
- Launch a profile-free broker on a private desktop with an explicit system environment, forward stdout/stderr incrementally and reap its process tree before cleanup.
- Return preparation/cleanup errors and add native regressions for overlap, policy ownership, environment isolation and residual resources; include them in Windows CI.

## Design rationale

The previous shared account and whole-DACL rollback required execution-long exclusion. Independent identity and rollback ownership allow safe overlap. Profile-free logon avoids accumulated user profiles, while the private desktop supports service-session startup.

## Validation

`make ci`, Windows vet/cross-compilation and output-cursor race tests passed. Native service and interactive sessions passed overlap, retained policies, live output, environment isolation and lifecycle cleanup checks. Account/profile/firewall inventory and ACL rollback checks passed.

The original curl/Schannel HTTPS test still fails with `SEC_E_NO_CREDENTIALS`, matching the pinned baseline on the same host. A temporary Go TLS client passed the unchanged network-policy assertions; curl compatibility remains unproven.

Follow-up: GitHub Windows CI rejected invocation passwords with error 2245. `NetUserAdd` defaults the display name to the account name, so the password's `Sbx!` prefix violates the complexity rule for the `sbx-…` display-name token. Use an independent prefix and shorter random groups that cannot contain account-name tokens, preserving 128 bits of random password entropy. Add deterministic complexity checks and native account creation to the existing invocation CI selector.

The follow-up passed `make ci`, Windows vet/cross-compilation, native backend selectors repeated ten times and execution selectors repeated three times with password complexity enabled. The native probe reproduced the original failure, created the repaired accounts successfully and restored the host's original policy. GitHub-hosted Windows CI remains a separate check.

## Key files

- `internal/backend/windows/backend.go`
- `internal/winrunner/profile_free_windows.go`
- `internal/winrunner/runner_windows.go`
- `tests/e2e/windows_overlap_test.go`

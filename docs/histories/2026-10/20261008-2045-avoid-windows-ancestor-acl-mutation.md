# Avoid Windows ancestor ACL mutation

## Background

Windows sandbox setup expanded every filesystem allow path into all of its
ancestors and edited each ancestor DACL. A workspace below a user profile could
therefore make setup recursively propagate a new inherited ACE across the whole
profile. Command execution remained stuck before the one-shot scheduled task was
created.

## Change

- Apply ACL grants only to paths explicitly present in the filesystem policy.
- Rely on the runner token's Windows traverse privilege for parent traversal.
- Add a Windows regression test that rejects implicit ancestor ACL plans.

This also reduces the sandbox's host mutation surface: selecting one workspace no
longer changes ACLs on a drive root or user profile root.

## Validation

- Windows package tests cover the generated ACL plan.
- The consuming device executor is rebuilt and exercised on a Windows host for
  workspace and full-access invocations.

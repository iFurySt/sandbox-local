# Windows private ancestor metadata

## Request

Fix npm EPERM when an allowed runtime is installed below private AppData parents, preserving read/write restrictions and bounded setup.

## Changes

- Add non-inheritable FILE_READ_ATTRIBUTES and FILE_TRAVERSE for allowed paths’ ancestors in the elevated backend. Explicit allow/deny roots and volume roots are excluded.
- Use NtSetSecurityObject for single-directory DACL changes and cleanup. Retain automatic-inheritance control flags using the native request bit; never traverse descendant trees or take ownership of system directories.
- Add native regressions for unchanged descendant ACLs, exact parent ACL restoration, private parent metadata, rejected directory listing and sibling file access, in open/offline modes.
- Keep the standard-user AppContainer implementation unchanged; this fix is validated against the elevated scheduled-task backend.

## Validation

Three native Windows x64 rounds passed the new unit and private-directory open/offline tests. Full existing transport/lifecycle matrix and repository CI are required before merge. The Engine consumer also validates actual bundled npm installs and all permission modes before its MR.

The broad native run also exposed a test fixture race: the PID marker could be observed between create and write. Publish the fixture marker atomically and wait for a valid nonzero PID, preserving the process-reaping assertions and deadlines.

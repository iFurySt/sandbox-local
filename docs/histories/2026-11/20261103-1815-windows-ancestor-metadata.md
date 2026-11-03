# Windows private ancestor metadata

## Request

Fix npm EPERM when an allowed runtime is installed below private AppData parents, preserving read/write restrictions and bounded setup.

## Changes

- Add non-inheritable FILE_READ_ATTRIBUTES, FILE_TRAVERSE and SYNCHRONIZE for allowed paths’ ancestors in the elevated backend. Explicit allow/deny roots and volume roots are excluded.
- Use NtSetSecurityObject for single-directory DACL changes and cleanup. Retain automatic-inheritance control flags using the native request bit; never traverse descendant trees or take ownership of system directories.
- Add native regressions for unchanged descendant ACLs, exact parent ACL restoration, private parent metadata, rejected directory listing and sibling file access, in open/offline modes.
- Keep the standard-user AppContainer implementation unchanged; this fix is validated against the elevated scheduled-task backend.

## Validation

Three native Windows x64 rounds passed the new unit/private-directory tests and the complete transport/lifecycle matrix (69 invocation attempts). Repository CI, local race checks, Windows vet and ARM64 cross-build also passed; GitHub Windows CI is required before merge. The Engine consumer separately validates actual bundled npm installs and all permission modes before its MR.

The broad native run also exposed a test fixture race: the PID marker could be observed between create and write. Publish the fixture marker atomically and wait for a valid nonzero PID, preserving the process-reaping assertions and deadlines.

Node/libuv opens a synchronous metadata handle, which also needs SYNCHRONIZE; the fixture now opens the same handle instead of relying on os.Stat’s cheaper attribute query. The descendant ACL regression supplies the production non-inheritable ACE, while retaining exact child and parent ACL equality assertions.

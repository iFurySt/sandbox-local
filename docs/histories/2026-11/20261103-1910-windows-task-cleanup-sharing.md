# Windows task IPC cleanup sharing

## Request

Finish Windows Executor regression with no scheduled-task, process or IPC residue before the consumer MR.

## Evidence

The complete consumer tool matrix passed, but its final inventory found two empty IPC directories after contained timeouts. Broker exit/stdin files were still briefly open without delete sharing when task termination returned. A controlled delayed-close native unit test failed three times on the old one-shot cleanup, with ERROR_SHARING_VIOLATION; the retry version passed, including caller-cancellation coverage.

## Change

Retry only sharing violations, access-denied and directory-not-empty failures for at most two seconds, checking context every 50 ms. Persistent failures remain errors. Extend existing process-lifetime E2E to offline cancellation and timeout while retaining descendant termination and resource inventory assertions.

## Validation

Local make ci and Windows vet passed. Native before/after unit checks passed their expected outcomes. Full native three-round E2E and GitHub Windows CI are required before merge; the consumer reruns its complete matrix and cleanup audit on the merged SDK.

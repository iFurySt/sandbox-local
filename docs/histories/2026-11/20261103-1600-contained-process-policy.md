# Windows contained process lifetime

Normal foreground completion must not leave restricted descendants running after the host restores ACLs and removes firewall rules. A native regression reproduced surviving descendants under both open and offline policies after cleanup.

Keep the job's kill-on-close limit armed for the whole restricted run, including normal foreground exit. The host returns foreground output promptly, reaps descendants, then restores policy. Add an explicit native policy-lifetime regression for both network modes and retain cancellation, output and concurrency coverage. Full-access execution in consumers that bypass the sandbox remains a separate host-process lifecycle.

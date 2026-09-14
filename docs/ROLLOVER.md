# Archive maintenance carry

`nq maintenance carry-from-archive` carries exactly one declaration that is
active when the command runs. It first verifies the specified current-schema
cold archive, reads its sealed database immutably, and requires the named
declaration's typed bytes, digest, ID, and active window to agree.

The successor store is selected only through its normal `--config` path. The
command requires a new maintenance ID, preserves `start_at`, `end_at`, scope,
actor, and reason exactly, and records an immutable archive lineage reference
beside the new declaration. Repeating the exact operation is idempotent;
changed source or destination material refuses.

It never carries expired or future declarations, renews a window, copies saved
check results or notification custody, activates a store, or grants authority.

```text
nq --config successor.toml --json maintenance carry-from-archive \
  --archive /path/to/archive \
  --source-maintenance-id old-id \
  --new-maintenance-id successor-id
```

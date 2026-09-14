# Archive maintenance carry

`nq maintenance carry-from-archive` carries exactly one declaration that is
active when the command runs. It first verifies the specified current-schema
cold archive, reads its sealed database immutably, and requires the named
declaration's typed bytes, digest, ID, and active window to agree.

The carry uses a contemporaneous immutable rollover inspection and refuses if
any retained saved-check, notification, legacy notification, or local-successor
acquisition remains pending or unknown. The source declaration must be current
at that inspection, and the command binds the canonical archive root, verified
seal, and verified database digest into its lineage receipt. The archive
namespace must remain quiescent while verification, inspection, and the carry
are performed; an operator records the corresponding stable inventory before
and after the procedure. A successor database that resolves to the archived
database, or a reused maintenance ID, refuses.

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

# NQ host-role runtime

This crate is the narrow bridge between the ratified host-role contract
carriers and NQ's schema-v7 append-only runtime ledger.

Every new checkpoint commits the exact authenticated dependency-generation
custody and trust-anchor identity used for that append. Equal generations are
deduplicated by immutable identity, while each checkpoint retains its own
binding. The store occurrence separately freezes one dependency-admission
trust-root identity at host-runtime initialization. Reopen authenticates every
historical generation against that independently stored root, validates
records introduced by a checkpoint against that exact generation, and
validates the cumulative graph only against the non-substituting union of
those reopened generations. A later generation may omit an older dependency;
it cannot select another root, reinterpret that older checkpoint, or replace
an older identity descriptor.

Schema-v6 checkpoints migrate as an exact `legacy_unbound` prefix. The
migration creates no dependency generation or trust anchor for history that
never stored one. Such history remains structurally readable but cannot be
semantically reopened by this runtime.

The runtime exposes checkpoint-pinned exact reads and a disposable inspector
projection, and resolves historical execution topology from the exact records
and dependency generation effective at execution time. Missing dependency
bytes remain committed-unavailable; substituted or malformed bytes remain
corrupt. Neither state is reconstructed from a caller's current generation.

This boundary detects substitution of current configuration, checkpoint
bindings, or retained dependency closures while the separately committed
store root remains intact. It does not claim authentication against a
coordinated offline replacement of the complete SQLite store, including that
root. Protecting and independently attesting the complete store is a
deployment/custody concern outside this crate's current qualification.

`nq.provider_intake.v1` is the only opaque ledger-resident external record
class. Other off-ledger dependencies may appear only as exact references in a
separately pinned closure snapshot. That snapshot supplies no bytes, semantics,
standing, or authority.

The crate owns no invocation scheduling, transport worker, IAM service,
Nightshift recurrence/posture, UI, authorization decision, actuation, or
deployed-engine correspondence claim.

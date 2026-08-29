# GROUP-ANCHOR generation-store mode-contract successor

Campaign: `GROUP-ANCHOR`
Slug: `generation-store-mode-contract-successor-v1`
Classification time: `2026-08-29T17:33:59Z`

## Predecessor and occurrence law

This is a distinct successor to terminal CALIPER at immutable commit
`74127fc0a121a0408ce6b5262ddf22f5e2d6f839`. CALIPER remains consumed.
This campaign does not reopen its C3 occurrence and creates no H, G, E,
admission, activation, timer, recurrence, or deployment authority.

The retained CALIPER record established that packaging deliberately owns the
shared sample parent as
`nq-passive-load-observer:nq-passive-load-reader` mode `02750`. Linux
therefore propagated SGID to CALIPER's requested `0750` generation leaf.
The observed `02750` leaf preserved the intended reader group and granted no
write permission to group or other.

## Resolved contract

A deployment-owned generation store satisfies the permission-mode contract
only when its complete Unix permission and special-bit field is exactly one of:

- `0750`: owner read/write/search and reader-group read/search; or
- `02750`: the same access bits plus intentional inherited SGID.

All other modes refuse. In particular, the contract refuses group-write,
other-write, missing reader-group access, sticky, setuid, and unexpected
special-bit combinations. The implementation does not clear inherited SGID
after directory creation.

The current operational doctrine now states this closed set. The shared
`require_sample_store` boundary enforces it for readiness and subsequent
observer operations; the readiness receipt continues to report the exact
observed mode.

## Qualification

Local fixture qualification completed from the exact CALIPER head:

- `cargo test -p nq-passive-load-helper --locked`: 34 passed, 1 ignored;
- process-boundary integration: 3 passed;
- `cargo clippy -p nq-passive-load-helper --all-targets --locked -- -D warnings`: passed;
- `git diff --check`: passed.

The focused qualification case accepts both `0750` and `02750`. Deterministic
negative controls refuse `0777`, `0770`, `0700`, `01750`, and `03750`.

## Result and successor boundary

Result: `implementation_qualified_local_fixture`.

This result resolves the source/doctrine mismatch and qualifies the local mode
predicate. It does not claim a live VM lifecycle result. Any lifecycle
qualification must use a fresh campaign and fresh occurrence, recheck the
actual deployment-owned pathname under the observer and provider identities,
and stop before authority if any exact entry fact differs.

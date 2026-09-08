# Native bounded factual predicate contract

CLASSIC-RETIREMENT candidate; not deployed or independent acceptance by itself.

`nq bounded-predicate admit --inventory I --profiles C --catalog-digest D
--concern Q --evaluated-at T --output R` admits a validated Monitor inventory
against exact catalog bytes. `replay --inventory I --profiles C --receipt R
--output -` recomputes the complete receipt. `support-evaluate` additionally
takes `--facts F` and requires a replayed positive primary predicate.

The compiled forms are queue depth <=17 or >=18; exists/readable/write access;
SQLite quick_check == ok and transaction acquired; free_bytes >=15032385536;
freelist_count >=5000000. Exact input-schema and expression equality selects a
compiled branch, never a runtime evaluator. Unknown forms refuse. Identities,
producer and manifest allowlists remain immutable content-bound input rather
than hardcoded application names. Changing these changes the receipt identity.

NQ owns typed fact evaluation, admission and replay. Monitor owns signed-source
independence and currentness. Nightshift owns recurrence/attention. AG-ng owns
authorization; Docket owns execution custody. None is silently substituted.

Native schemas are `nq.bounded-predicate-admission/v1`,
`nq.bounded-predicate-support-evaluation/v1`, and
`nq.bounded-predicate-replay/v1`. Existing catalog schema is retained as a
content-bound data format, not as an execution dependency on classic.

Admission binds the full inventory/catalog, exact occurrence, profile and
input-schema identities, producer, and observation. Missing/malformed facts,
acquisition/refusal, ambiguous bindings, stale/future observations or replay
mismatch refuse, not false or established. A well-typed false predicate is
recorded false, but cannot serve as a positive support anchor.

Explicit semantic tightening: native admission always uses an exclusive
300-second maximum, narrowed by profile and observation bounds. Absent/null
producer validity cannot grant unlimited reliance. Historical classic admitted
optional/inclusive bounds; its original qualification is not transferred.
Neither version establishes uninterrupted world truth or deployment identity.

Artifacts are bounded to 2 MiB. Offline replay does not need a daemon, database,
network, classic source, or classic executable. The CLI deliberately does not
grant a scheduler, routing decision or action authority. Repository fixtures
retain the donor factual requirements; positive/refusal/indeterminate/replay
controls run against native Rust implementations.

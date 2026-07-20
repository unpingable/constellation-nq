# nq-store public SQLite views

These views are the only supported direct-SQL surface. Consumers must open the
database read-only and bound result size and execution time. Saved SQL is an
operator query; it never becomes detector semantics.

## `public_finding_snapshot_v3`

One row per opaque NQ-owned finding ID. The view follows the rebuildable
`finding_current` pointer into immutable `finding_events` and exposes detector,
profile key/version/digest/semantic identity, instance, subject, condition,
visibility, operator-work, severity, freshness, basis, refusal, origin, and
time fields independently. It joins the exact immutable evaluation identity
that produced the current event. A `cannot_evaluate` result exposes the linked
canonical evaluation refusal; it is never reconstructed from condition state
or a coarse code.

`evidence_json` is an ordered JSON array. Every element carries the admitted
report ID and semantic digest, optional observation ordinal, and observed and
received times. A consumer must not reconstruct finding IDs or treat an empty
array as a healthy result.

The preceding V2 finding view is not retained as an alias because it cannot
represent mandatory profile semantic identity and typed evaluation-refusal
linkage. API callers receive an explicit requirement to use V3.

## `public_status_snapshot_v1`

One row per `(component_kind, component_id)` for daemon, database, profile
catalog, admission, scheduler, instance, evaluation, and notification health.
It follows `status_current` into immutable `status_events`; the detail document
is canonical JSON. Current typed instance results use
`nq.collection_outcome.v1` for non-admitted outcomes and
`nq.collection_outcome.v2` for admitted outcomes carrying their exact ordered
`EvaluationEnvelopeV2` set. Product status/API/CLI code reopens them through
the typed V3 status DTO and verifies any rejected result against its exact
linked custody refusal. V3 also selects the latest exact evaluation in every
complete semantic lineage from immutable evaluation history. The SQL `code`
column remains a non-testimonial index.

`nq.status_snapshot.v2` remains a collection-only compatibility DTO. It fails
explicitly when any governed evaluation exists rather than dropping that
testimony; current callers use `nq.status_snapshot.v3` and `/v3/status`.

Evaluation history is intentionally not exposed as an unconstrained direct-SQL
view. `/v1/evaluations` and `nq evaluations export` return bounded
`nq.evaluation_history.v1` pages ordered by the store-wide monotone
`evaluation_sequence`. The first page freezes an inclusive `through_sequence`;
continuations use an exclusive `after_sequence`, preventing later appends or
the 1,000-row page ceiling from silently hiding records. Each record carries
the complete persisted `EvaluationEnvelopeV2` around `EvaluationResultV1`.
For collection-triggered evaluations, this durable sequence is itself part of
the V2 collection carrier: reopening compares the carrier directly with
ascending `evaluation_sequence`, so a coherent row reorder is not normalized
into an equal unordered set. Each call reads at most the requested number of
evaluation rows and only the
latest prior finding state needed to seed each lineage represented on that
page; it does not materialize the full immutable history before applying the
limit. Missing or non-contiguous sequences, an unfrozen continuation, or a
page whose cardinality disagrees with its frozen bounds fails closed.

Finding and rejected-custody exports instead page in lexical order by their
immutable opaque IDs. That order is repeatable for a fixed database, but it is
not a frozen snapshot of a concurrently changing live store: a later insert
whose ID sorts at or before an already-returned cursor is outside that
traversal. Use a verified backup or cold archive when exhaustive snapshot
enumeration is required. Archive verification pages an immutable database and
therefore does not have this live-append limitation.

## `public_notification_status_v1`

One row per immutable outbox item. Delivery state is derived from immutable
attempts and the configured attempt ceiling. `pending`, `delivered`, and
`failed` remain visible without rewriting the outbox item.

Raw profile report payloads remain intentionally absent from these projections.
They stay bounded canonical JSON on admitted reports and observations and are
interpreted only by their compiled profile module. Profile identity needed to
interpret a governed finding is explicit in V3 rather than inferred from raw
payloads.

# nq-store public SQLite views

These views are the only supported direct-SQL surface. Consumers must open the
database read-only and bound result size and execution time. Saved SQL is an
operator query; it never becomes detector semantics.

## `public_finding_snapshot_v2`

One row per opaque NQ-owned finding ID. The view follows the rebuildable
`finding_current` pointer into immutable `finding_events` and exposes detector,
profile, instance, subject, condition, visibility, operator-work, severity,
freshness, basis, refusal, origin, and time fields independently.

`evidence_json` is an ordered JSON array. Every element carries the admitted
report ID and semantic digest, optional observation ordinal, and observed and
received times. A consumer must not reconstruct finding IDs or treat an empty
array as a healthy result.

## `public_status_snapshot_v1`

One row per `(component_kind, component_id)` for daemon, database, profile
catalog, admission, scheduler, instance, evaluation, and notification health.
It follows `status_current` into immutable `status_events`; the detail document
is canonical JSON.

## `public_notification_status_v1`

One row per immutable outbox item. Delivery state is derived from immutable
attempts and the configured attempt ceiling. `pending`, `delivered`, and
`failed` remain visible without rewriting the outbox item.

Profile payloads are intentionally absent from these projections. They remain
bounded canonical JSON on admitted reports and observations and are interpreted
only by their compiled profile module.

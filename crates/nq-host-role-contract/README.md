# NQ host-role runtime contract

This crate is the repository-native carrier and validation boundary for
Host-Role Runtime Contract v1. Its normative source is the immutable
skunkworks decision:

- commit `d8aba7b728236120e0dfd05ba6feb3e64fc3647d`;
- tree `b88a7a9ad380ed770d936f54f6da7eef1a9a15fe`;
- path `audits/nq-host-role-runtime-contract-v1`.

The package embeds and hashes the exact 26 primary schemas plus
`nq.host_role_common.v1`. It also carries a mechanically generated 50-record
specimen from that decision and replays it in the Rust conformance suite.

## Stable seam

- `RuntimeSchema` is the closed set of supported primary schemas.
- `RuntimeRecord` exposes one dedicated carrier variant per schema.
- `ValidatedRuntimeRecord` owns exact canonical bytes, their digest, the
  declared record identity, and the parsed typed carrier.
- `RuntimeRecordSet` validates a closed exact-reference graph.
- `IdentityCatalog` resolves production identity descriptors and supports a
  deterministic `CatalogSnapshot` for restart-safe persistence.
- `ValidationContext` supplies admitted identity descriptors and exact
  externally retained record references.

Construction remains private. Callers enter through
`ValidatedRuntimeRecord::decode_canonical` or
`ValidatedRuntimeRecord::validate_value`; unchecked builders are deliberately
absent.

## Enforced boundaries

The implementation rejects unknown schema/fields, noncanonical input bytes,
descriptor or immutable-record substitution, unresolved exact references,
reference cycles, illegal lifecycle edges and forks, topology/generation
substitution, custody-before-launch violations, delivery chain forks,
incoherent retry/capacity policy, restore quarantine bypass, incomplete
terminal decommission, and Nightshift-owned recurrence/posture fields.

Validation establishes contract conformance only. It does not authenticate a
producer, admit a production identity descriptor, authorize invocation,
schedule diagnostics, establish Nightshift posture or reliance, authorize
action, or prove correspondence with a deployed engine.

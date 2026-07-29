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
Every carrier is executed against the embedded JSON Schema as well as the
closed Rust semantic checks. A vocabulary meta-test refuses future embedded
schema keywords, formats, or patterns that the local executor does not
implement.

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

The graph validation closes administrative authorization over a sorted,
one-use authority-neutral consumer set; refuses overlapping node activations;
binds accepted invocation, reservation, and launch records to one exact
request/topology/time closure; and validates delivery
envelope→attempt→receipt→state-chain joins. The quarantine specimen is a
`begin_restore` decision. A `complete_restore` operation is valid only for an
`eligible_enrolled_inactive` proof and its complete resulting topology
closure.

Construction remains private. Callers enter through
`ValidatedRuntimeRecord::decode_canonical` or
`ValidatedRuntimeRecord::validate_value`; unchecked builders are deliberately
absent.

## Enforced boundaries

The implementation rejects unknown schema/fields, noncanonical input bytes,
descriptor or immutable-record substitution, unresolved exact references,
reference cycles, replayed or scope-substituted grants, illegal lifecycle
edges and forks, overlapping activation/key intervals, topology/generation
substitution, custody-before-launch violations, delivery receipt borrowing
and chain forks, incoherent retry/capacity policy, restore quarantine bypass,
incomplete terminal decommission, and Nightshift-owned
recurrence/posture fields.

Validation establishes contract conformance only. It does not authenticate a
producer, admit a production identity descriptor, authorize invocation,
schedule diagnostics, establish Nightshift posture or reliance, authorize
action, or prove correspondence with a deployed engine.

## Formal reference

Consumer-indexed composition should follow the independently proved
settlement–reliance seam at immutable formalization commit
`a198bc539f9be10b77816446b07ecb115245c8f9`: native results remain native,
the seam checks explicit correspondence obligations, and the computed
reliance entitlement stops before authorization. This is a reference pattern,
not a claim that Lean proves this Rust validator or a deployed runtime.

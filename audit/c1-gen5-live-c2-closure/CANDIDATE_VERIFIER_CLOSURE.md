# C1 Gen5 C2 — candidate verifier closure

Date: 2026-08-12

Status: **DEVELOPMENT IMPLEMENTATION CLOSED — NOT A QUALIFICATION RECORD**

This checkpoint supersedes only the gate-35 blocker described in
`RESUMPTION.md`. It does not rewrite that earlier checkpoint or any historical
campaign evidence. No candidate was frozen, no production trust root or
certificate was issued, and no qualification claim was earned.

## Closed production chain

The current product graph has exactly one bounded candidate-verification
chain:

```
fixed root-owned qualification trust source
  -> exact canonical trust-root record
  -> RFC-8785 canonical candidate certificate
  -> Ed25519 domain-separated authentication
  -> exact commit/tree/candidate derivations
  -> exact manifest/source-map/toolchain/target/assumption correspondence
  -> /proc/self/exe runtime-artifact measurement
  -> private authenticated candidate record
  -> opaque process-local verifier result
  -> Store::c2_lifecycle_v1
```

The qualification trust source is distinct from runtime A1/A2 and is fixed at
`/etc/nq/c2-qualification-trust-root.v1.json`. The implementation opens each
path component without following symlinks and verifies root custody and
non-writability before accepting the terminal regular file.

Certificate and manifest bytes remain evidence. The opaque verifier result is
nonserializable, non-Clone, non-Copy, has no public fields or raw-parts
constructor, carries the verification process ID, and is rechecked before each
Store admission. Exact certificate replay is reusable evidence, not authority:
after exec/restart the fixed trust source, certificate signature, manifest
basis, and running image are verified again to mint a fresh result.

## Development evidence

- Candidate verifier unit surface: 11/11 PASS, including canonical parsing,
  malformed/unknown/duplicate input, wrong issuer, signature substitution,
  candidate/commit/tree/manifest/runtime/evidence/toolchain/target/assumption
  substitution, exact replay, public facade reachability, and real exec/re-entry.
- Public lifecycle facade: 2/2 PASS; six embedded compile-fail specimens PASS.
- Live authority noninjectability: 1/1 harness PASS; four compile-fail
  specimens and one inert-evidence control PASS.
- Governed routes: 2/2 PASS; hostile integration: 4/4 PASS; restart
  integration: 5/5 PASS.
- Call-graph verifier: 39/39 PASS. The fixed census now proves the sole
  certificate-to-lifecycle chain and the absence of a Store mutation in the
  detached verifier.
- Mutator census: PASS; candidate verification adds no persistent mutator.
- Formal lifecycle build: PASS, 19 jobs; the normative formal contract was not
  changed by this closure.
- Isolated source-I/O crash execution: all 70 manifest-derived cuts PASS; the
  aggregate harness reports 1/1 PASS with 522 filtered.
- Final-source broad library subset: 513/513 PASS after filtering only the
  already-run aggregate crash test and ten frozen-candidate asset checks.
  Those ten checks still refuse because their capsule-bound semantic inventory
  identifies the pre-campaign candidate rather than this dirty development
  tree; they are intentionally left for candidate freeze. Five historical
  Gen4 trybuild snapshots also retain their intended compile prohibitions but
  differ only in the printed qualification of `StoreWriterSession`; their
  snapshots were not blessed.

## Qualification boundary

The verifier authenticates the exact issuer-attested qualification evidence
identity. The future qualification campaign must still establish and record:

- the Git commit-to-tree relation;
- manifest source-map membership and exact blob correspondence in that tree;
- the exact toolchain/target/assumption basis;
- runtime-artifact derivation and measurement premises;
- the earned claim and complete qualification packet;
- the production trust-root installation and candidate certificate issuance.

Those are qualification duties, not alternate runtime authority constructors.
Cryptographic security, Git object semantics, procfs measurement semantics,
and filesystem custody remain executable/qualification premises rather than
semantic theorems.

Development acceptance gate 35 is closed. Together with the preserved and
revalidated gates 1--34, the complete Live C2 development score is 35/35.

# NQ-NG to Nightshift admission boundary

This document records the exact source-side boundary used by canonical
Nightshift. It does not authorize deployment, replacement of Classic NQ, or a
production cutover.

## Production-contract shape

NQ-NG owns `nq.diagnostic_execution.v2`. A bounded `diagnostics execute`
operation commits the canonical artifact in the same store transaction as its
local run, provider intake, admission or refusal, and evaluation history.

Nightshift does not infer that history from delivered artifact bytes. For each
delivered artifact it invokes the configured NQ-NG executable through:

```text
nq --config CONFIG --json diagnostics qualify ARTIFACT_ID
```

The read-only operation reopens the exact local history and emits
`nq.diagnostic_admission_provenance.v1` for historical ordinary acquisitions,
or `nq.diagnostic_admission_provenance.v2` when the original acquisition
committed a signed Standing continuity prerequisite before provider
invocation. The common carrier binds:

- the NQ store-genesis source identity;
- the exact v2 artifact identity, canonical-byte digest, and length;
- the exact run, optional evaluation, completion, and commitment times;
- the provider intake, raw-byte, source-admission, admission-context, and
  profile-semantic identities;
- the admitted judgment, governed refusal, or acquisition-failure
  disposition.

Imported artifact custody cannot acquire this provenance. An exact replay is
read-only and returns the same content identity; it does not create a new
observation or refresh any evidence time.

The carrier establishes historical evidence eligibility only. Nightshift owns
observation composition and currentness. NQ-NG grants no standing,
authorization, action, or permission to execute through this boundary.

The v2 form additionally embeds the exact signed Standing authority and
acquisition commitment, NQ-owned acquisition basis and intent, and the closed
invocation-start/intake-complete phase chain. See
`CONTINUITY_AUTHORITY_CARRIER_V1.md`. It cannot be retrofitted to a historical
v1 acquisition. In the absence of independently authenticated substrate-origin
evidence, Nightshift retains the carrier but leaves physical attribution
unresolved.

## Relation to Classic NQ

Classic NQ's stable `nq.finding_snapshot.v1` export was the production input to
the retired Nightshift Watchbill runtime. It remains a legitimate Classic NQ
consumer contract, but it is not the canonical-runtime admission contract.
The historical Watchbill adapter cannot be promoted merely to make a current
cycle run: it does not carry the exact v2 artifact, provider-intake,
profile-semantic, and local-store provenance required by the canonical
runtime.

Classic NQ's fleet `ssh://` reader is likewise a fleet-index liveness
transport, not this admission boundary. It does not authenticate or qualify an
NQ-NG diagnostic execution for Nightshift.

## Executable and deployment gate

The executable name is operationally hazardous: Debian's unrelated `nq`
package also owns `/usr/bin/nq`. NQ-NG packaging declares `Conflicts: nq` and
does not silently replace it. A deployment must verify the configured binary
supports the exact read boundary before enabling Nightshift:

```sh
/absolute/path/to/nq --help
/absolute/path/to/nq diagnostics qualify --help
```

Both checks are required. Debian's unrelated queueing utility rejects global
`--help` but can return success for arbitrary trailing command words; an older
NQ-NG build supports global help but rejects the qualifier subcommand.

Passing that preflight does not authorize an NQ-NG cutover. The selected
successor remains non-authoritative until its separate deployment,
qualification, identity, and authority-switch gates are satisfied.

## Subject and vantage identity

The v2 artifact binds exact `SemanticIdentityV1` values for subject scope and
vantage. Nightshift's policy identity includes the complete inventory binding,
including vantage, so different configured vantages remain in different
observation lineages. Neither repository currently defines a DNS-hostname
alias registry or canonicalizes multiple hostnames into one subject. A real
host must therefore receive one explicit canonical subject and vantage
identity before ingestion; DNS similarity is not identity evidence.

## Qualification evidence

The focused executable-boundary tests are:

```sh
cargo test --locked -p nq-app --test admin_lifecycle \
  doctor_and_restore_refuse_resealed_local_artifact_semantic_substitution -- --exact
cargo test --locked -p nq-app --test admin_lifecycle \
  diagnostic_export_import_restart_and_same_operation_replay_preserve_exact_receipt -- --exact
```

The first invokes the actual `nq` test binary, emits v2 locally, qualifies it
after process restart, proves exact replay convergence, and then exercises
semantic substitution refusal. The second proves imported custody cannot be
relabelled as local admission provenance. Nightshift separately qualifies its
process adapter, strict carrier parser, exact query binding, currentness, and
lineage behavior.

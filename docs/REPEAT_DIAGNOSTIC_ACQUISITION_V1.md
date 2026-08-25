# Repeat diagnostic acquisition v1

Status: qualified production contract for deliberate, bounded successor
acquisitions of an already admitted watcher. It defines no cadence, timer,
monitor, or automatic retry.

## Ownership and authority

The active watcher admission fixes the diagnostic contract: watcher instance,
subject, profile/question semantics, threshold, provider execution identity,
scope, vantage, and origin requirement. An operator with existing custody of
the local NQ maintenance command may request one deliberate successor. This is
the same bounded collection authority already used by `nq collect`; it is not
Nightshift currentness authority, Pulse evidence, AG work authority, or a new
scheduler authority.

Changing any watcher semantic requires ordinary watcher rotation/re-admission.
It cannot be smuggled into a successor occurrence.

## Three different operations

```text
replay(A)
  = reopen exact completed A
  = no origin helper
  = no diagnostic provider
  = no new timestamp or evidence

acquire-next(W, trigger A2)
  = one caller-owned deliberate trigger identity
  = fresh V3 origin attestation for A2
  = one provider invocation for A2
  = one append-only artifact/provenance result

restart
  = reopen custody
  = no acquisition
```

The acquisition ID is also the duplicate-delivery trigger identity. Exact
redelivery converges on the completed occurrence. A genuinely separate request
must carry a different caller-owned acquisition ID. There is no mutable
`current_acquisition`; SQLite sequence values are read-model ordering only.

## Occurrence-scoped diagnostic selection

The original bootstrap artifact retains
`nq.fresh_single_admitted_report/v1`, whose exact meaning requires no prior
matching history. A deliberate successor uses the new closed selection rule:

```text
nq.deliberate_successor_single_admitted_report/v1
```

It requires prior matching history for the exact watcher contract, retains
that history, excludes it from the new detector input, and selects exactly the
newly admitted report produced by the exact successor acquisition. This makes
the existing `nq.diagnostic_execution.v2` input accounting truthful without
rewriting A1 or evaluating a synthetic blend of historical reports.

Artifact identity is not acquisition identity. Equal measured values or equal
condition states do not collapse two deliberate occurrences. Reusing A1 bytes
as A2 refuses because V3 intent, run, intake, artifact, and admission
provenance remain exact.

## V3 and provider boundary

Every new successor acquisition uses the already-qualified V3 origin path.
The coordinate may remain equal, but the acquisition basis, attestation,
intent, invocation fence, intake, and provenance are occurrence-specific.
V1, V2, another origin profile, another coordinate, imported custody, or a
different watcher cannot satisfy this command.

The per-watcher kernel lock covers duplicate reconciliation, origin
attestation, provider dispatch, intake, and completion. Duplicate delivery of
one trigger converges. Two different deliberate trigger IDs serialize and
remain two append-only occurrences.

## Failure and restart law

- Failure before the origin prerequisite is established creates no provider
  invocation and no acquisition occurrence. The same trigger may be attempted
  again because nothing ambiguous crossed the provider boundary.
- Once `provider_invocation_started` is durable, a missing completion is an
  outcome-unknown occurrence. The same trigger refuses and cannot invoke the
  provider again. A later deliberate request needs a new acquisition ID.
- A bounded provider failure that reaches durable intake is completed evidence,
  not an automatic retry request. Exact replay returns that failure artifact.
- Restart only reopens these states. It never creates a trigger or provider
  invocation.

No uncontrolled retry loop exists.

## Nightshift and support

Nightshift consumes an explicitly selected diagnostic artifact. It does not
request successors through this contract. Pulse support remains an independent
lineage: neither support production nor currentness retry creates an NQ
diagnostic occurrence. A later Nightshift cycle may combine an exact successor
artifact with independently applicable support under existing policy.

## Commands

One deliberate successor:

```sh
/absolute/path/to/nq --config CONFIG diagnostics \
  acquire-next-linode-origin WATCHER \
  --acquisition-id CALLER_OWNED_TRIGGER \
  --expected-instance-id-sha256 sha256:EXPECTED \
  --origin-helper /absolute/path/to/nq-linode-origin-helper \
  --origin-helper-sha256 sha256:HELPER \
  --origin-helper-account nq-origin-helper \
  --origin-helper-public-key /absolute/path/to/public-key.hex
```

Exact replay:

```sh
/absolute/path/to/nq --config CONFIG diagnostics \
  replay-substrate-origin WATCHER \
  --acquisition-id EXACT_ACQUISITION
```

The replay command deliberately has no helper path, origin source, provider,
retry, or scheduling argument.

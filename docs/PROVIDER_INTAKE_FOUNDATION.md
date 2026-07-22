# Provider-intake foundation

Status: post-`v0.1.0` architecture record for the bounded
`campaign/provider-intake-foundation` campaign.

## Release separation

The qualified `v0.1.0` release remains the combined local operational-evidence
vertical slice. Its immutable release identity is:

- tag `v0.1.0`;
- commit `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`;
- tree `f7f244d69461e342997850869cb243abdbdedf27`;
- Debian artifact `nq-ng 0.1.0 amd64`;
- artifact SHA-256
  `24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`.

This campaign begins from the later record-only commit
`e3c451f9722cb81dd22af25c52b264e6b888ed81`, tree
`328c41c97f11e57500d9207824d35b086a889454`. Nothing in this record changes,
reinterprets, or extends the claim established by the tagged release. The
provider-intake implementation is post-release candidate work and is not part
of `v0.1.0`.

## Constitutional boundary

An acquisition provider owns sensing and its native account of an acquisition.
It may own provider-local scheduling, sensor or helper lifecycle, buffering,
and retry before NQ durably acknowledges an attempt. It may report its native
success, failure, timeout, refusal, partial result, loss, observation time,
coverage, structured errors, checkpoint, sequence, and declared provenance.

NQ owns the boundary at which those provider outputs become durable candidate
evidence and may proceed to NQ judgment. NQ retains:

- provider admission and the trusted binding of provider identity;
- request, attempt, and admission identity;
- exact raw-byte custody;
- protocol correlation and normalization;
- profile-semantic admission or refusal;
- detector evaluation, freshness, and visibility;
- stable refusal linkage and indeterminacy;
- durable sequence and watermark allocation;
- atomic publication of the canonical collection result;
- historical reopening and correspondence verification.

A provider may state only its native observation and acquisition facts. It may
not state or inject report admission, profile validity, detector state, finding
severity, remediation, health, testimonial sufficiency, claim entitlement,
standing, ratification, authority, or permission to act. Those fields are not
part of the provider-intake vocabulary.

Provider admission and report admission are separate judgments:

```text
ProviderAdmission
    = this exact provider implementation may submit candidate evidence
      under this exact bounded contract

ReportAdmission
    = these exact candidate bytes passed the independently compiled NQ
      profile and admission law under their bound context
```

The first judgment does not imply the second. Neither implies truth,
freshness, completeness, detector presence, health, testimony for an external
claim, or authority.

## Why a process split is not the boundary

In `v0.1.0`, NQ schedules and launches the local helper, verifies the retained
executable descriptors and Unix peer identity, captures the response, assigns
custody, validates the report, evaluates detectors, and commits the result.
Moving those calls behind another daemon or RPC without making identity,
native outcome, raw custody, replay, and durable acknowledgment explicit would
only relocate the same ambiguity.

The provider-intake boundary is therefore semantic and durable before it is
physical. This campaign creates no watcher daemon, network service, POST
endpoint, message queue, plugin host, or remote transport. The existing
NQ-controlled local helper remains the only live provider and continues to use
the existing stdio and authenticated Unix carriers.

## Local-provider identity and admission

The current `AdmissionLock`, durable `admission_records`, and binding-event
history remain authoritative for admitting the local helper provider. The
foundation derives a provider identity from NQ-verified material rather than
accepting an identity asserted in a response.

The local implementation uses an NQ-specific type family headed by
`ProviderIdentityV1`. Its bound material includes, as applicable:

- the provider-intake schema and local-provider kind;
- an NQ-derived provider semantic identity;
- the provider admission and active binding identities;
- the retained executable/artifact and execution-identity digests;
- the admitted configuration digest;
- the exact helper protocol identity;
- the conformance-corpus identity;
- the compiled profile, evaluator, admission-context, and capability-grant
  identities.

Runtime authority is carried by `VerifiedProvider`, whose fields are private
and which cannot be deserialized or directly constructed by an intake caller.
NQ constructs it only after verifying the active binding, retained launch
identity, and corresponding durable admission. In particular,
`EvidenceReport.backend` remains declared, untrusted provenance; a provider
cannot become trusted or change its trusted identity by naming an
implementation, version, tool, or digest there.

The provider record carries the evaluator artifact ratified by that durable
source admission; it does not substitute the digest of whichever `nq` or
`nqd` front end happens to transport an intake. Detector evaluations retain
their separate exact evaluator-artifact checks. This preserves the existing
cross-process operator/daemon workflow without turning a front-end binary into
provider identity.

Rotation or revocation ends the old provider admission for new live intake.
Historical receipts remain reopenable as history, but reopening them does not
reactivate the provider.

This first provider admission is intentionally not a general provider registry.
It is derived one-to-one from an exact local helper `AdmissionLock`, and current
eligibility is still gated by that instance's active binding. The persisted
`source_admitted_at`, `derived_at`, and `derivation_kind` fields distinguish the
source decision from when and why its provider contract was materialized; they
do not expand the contract or become provider-supplied identity. Independent
provider epochs, validity windows, provider-specific revocation records, and
non-helper capability vocabularies remain outside this campaign.

The derived provider-admission contract is not a static subject/scope/vantage
allowlist. Those values are chosen and bounded by NQ in each configured watcher
request and are then included in the immutable intake context and replay
identity. This is sufficient for the sole local-helper producer, but a future
independent provider with broader admission scope would need an explicit
admission law for its permitted subjects, scopes, vantages, capabilities,
validity epoch, and replacement behavior.

## Intake object and identity

`ProviderAttempt` binds the exact verified provider and intended collection
before invocation. Three identities remain distinct:

- `request_id` identifies the correlated helper-protocol exchange;
- `attempt_id` is the provider-intake and idempotency identity;
- `run_id` identifies the current local watcher-run subtype.

The attempt also binds the NQ request, provider admission, profile semantic
identity, evaluator artifact, admission context, checkpoint contract, carrier,
and the request collection bounds and deadline established before dispatch.
The runner separately enforces the NQ-configured operating-system hard limits,
which the post-invocation native resource outcome records. NQ assigns these
identities and bounds; the provider does not mint them by filling fields in a
response.

The admission-time dry exchange uses a non-durable candidate attempt. It may
exercise the same capture and response interpreter, but it cannot create a
durable provider intake or acknowledgment.

After invocation, NQ constructs `ProviderIntakeV1` exactly once from the
verified attempt and `RunCapture`. Its versioned record preserves:

- request, attempt, run, provider, admission, profile, evaluator, subject,
  scope, vantage, capability, and checkpoint-contract identity;
- NQ attempt start, finish, and receive times;
- the complete native acquisition outcome, including dependent timeout phase,
  exit, disconnect, framing, resource, and partial-capture facts;
- exact raw bytes, their NQ-derived length and SHA-256 digest;
- the parsed candidate response, when one exists;
- report observation time, status, coverage, incompleteness, structured
  errors, declared provenance, and candidate checkpoint;
- a reserved provider-local sequence slot, which the schema-v4 local-helper
  contract requires to remain absent;
- an NQ-derived context and intake digest.

Callers do not independently supply the raw digest, context digest, response
interpretation, or intake digest. Parsed candidate evidence never replaces
the exact raw bytes from which it was obtained.

The response interpretation keeps the planes separate:

```text
native AcquisitionOutcome
    -> no parseable response, protocol rejection, or correlated HelperResponse

correlated HelperResponse
    -> provider-native refusal or candidate EvidenceReport

candidate EvidenceReport
    -> NQ normalization and profile admission or refusal

admitted report
    -> NQ detector evaluation and publication
```

A completed provider exchange is not report admission. A provider-native
refusal or operational failure is not allowed to impersonate an NQ profile
refusal. NQ records the source outcome and performs the explicit normalization
that determines the canonical downstream result.

## Schema-v4 custody model

Schema v4 uses the provider-intake parent-record design. It adds these
append-only relations:

- `provider_intake_attempts` for the versioned intake identity, context,
  native outcome, exact capture, and digests;
- `local_watcher_provider_intakes` for the one-to-one local watcher-run subtype
  link;
- `provider_intake_acknowledgments` for the acknowledgment returned only after
  its enclosing transaction commits;
- `legacy_v3_watcher_run_intake_gaps` for facts that the released v3 store did
  not retain and therefore cannot prove.

`CollectionInput.intake` is mandatory for every new admitted or non-success
collection. The current watcher run remains part of the custody proof; it is
not replaced by a nullable provider reference or an untracked submission lane.
For new v4 history, the required chain is:

```text
provider admission and active binding
    -> provider intake attempt
    -> local watcher run
    -> exact raw capture
    -> raw submission, when a protocol submission exists
    -> admission or linked refusal
    -> evaluations, findings, and status
    -> durable intake acknowledgment
```

Despite the parent-record shape, schema v4 is not yet provider-neutral. Every
`provider_intake_attempts.provider_admission_id` references
`local_provider_admissions`, every live intake has exactly one
`local_watcher_provider_intakes` origin, and the core provider-kind vocabulary
is closed to the local helper. An independently deployed provider would require
an explicit new admitted-provider subtype and corresponding schema/type laws;
it cannot use these rows by impersonating a watcher run.

When both the intake and `raw_submissions` retain bytes, their content and
digest must agree exactly. The intake retains the bounded raw capture for
timeouts, disconnects, overflow, EOF, malformed responses, and other outcomes
that cannot become a parsed protocol submission. An admitted report can never
exist without the exact provider attempt and raw provenance that produced it;
rejected custody can never exist without its linked structured refusal.

Schema and application validation enforce an exclusive historical law: every
watcher run has either one real intake, local-provider link, and acknowledgment,
or one explicit released-v3 gap record, never both and never neither.

## Released-v3 treatment

The exact released schema is frozen as `crates/nq-store/src/schema_v3.sql`.
Migration first validates that complete v3 definition, creates and verifies a
backup, and then installs the additive v4 relations and triggers in one
transaction.

Every pre-v4 watcher run is enumerated in
`legacy_v3_watcher_run_intake_gaps`. It receives no synthetic provider intake,
raw capture, provider-attempt identity, or acknowledgment. The migration may
derive a local-provider admission contract from the exact preexisting admission
facts for future use, but it does not attach that contract to an old run or
pretend the run crossed the v4 intake boundary. This is necessary because v3
discarded exact stdout bytes for several failed or partial acquisition
outcomes. An empty byte string, reconstructed attempt identity, or fabricated
receipt would falsely claim evidence that was never stored.

The original run, submission, admission/refusal, evaluation, finding, status,
and sequence meaning remains unchanged. Backup, archive, and historical
verification report the explicit legacy gap rather than treating it as a v4
intake or as corruption. New v4 commits cannot use the legacy-gap path.

## Replay and idempotency

Replay classification occurs before profile validation, detector evaluation,
or finding transitions. A submission is an exact replay only when all of the
following match the stored attempt:

- provider and provider-admission identity;
- attempt identity;
- exact raw digest and bytes;
- request and bound context, including subject, scope, vantage, profile,
  evaluator, capabilities, and checkpoint contract;
- native outcome and interpretation.

An exact replay returns the original stored acknowledgment and canonical
`CollectionOutcome`. It does not re-admit the report, rerun detectors, allocate
new sequence or watermark values, revise findings, or reinterpret the attempt
under a changed current context.

Reusing an attempt identity with different bytes, native outcome, provider,
admission, request, subject, scope, vantage, profile, evaluator, capability, or
checkpoint context is an intake conflict and fails closed. A live submission
must first satisfy the current provider admission; revocation or replacement
therefore blocks reuse under stale authority. A separate read-only historical
operation may reopen the stored receipt without performing a live submission.

## Atomic commit and durable acknowledgment

`DurableIntakeAcknowledgment` means exactly:

> NQ durably committed this exact provider attempt and its canonical downstream
> outcome.

The acknowledgment document directly binds the acknowledgment, intake,
attempt, run, provider-admission, and status-event identities; the intake and
raw digests; the canonical outcome digest; and a transaction-recorded
timestamp. Report
sequence, evaluations, findings, and linked refusal are not duplicated as
direct acknowledgment fields. They are transitively associated only through
the validated intake/run/status custody graph committed in the same
transaction. The acknowledgment deliberately contains no `success`, `healthy`,
`admitted`, `entitled`, `ratified`, or `authorized` Boolean.

The acknowledgment is inserted in the same immediate SQLite transaction as
the provider attempt, watcher run, raw custody, report or refusal, evaluations,
findings, status, sequence, and watermark. The store returns it to NQ's
collection pipeline only after that transaction commits. The current local
helper does not receive this acknowledgment; a future provider adapter may
consume it only with these exact semantics. A builder error, constraint
failure, process interruption, or commit failure exposes neither an
acknowledgment nor a partial intake chain.

No reader may observe:

- an acknowledgment without its complete durable history;
- an admitted report without exact raw custody;
- a finding without its evaluation;
- rejected evidence without its refusal;
- a semantic result linked to another provider attempt;
- checkpoint advancement before the corresponding admitted commit and
  acknowledgment.

Checkpoint semantics remain deliberately narrower than generic receipt of
bytes:

```text
provider candidate checkpoint
    -> profile-admitted report
    -> atomic collection commit and durable acknowledgment
    -> checkpoint becomes eligible for the next NQ request
```

A dry exchange, native failure, provider refusal, protocol rejection,
profile-refused report, replay conflict, or rolled-back transaction does not
advance the checkpoint.

A schema-v3 report may retain its historical `next_checkpoint_json` after
migration, but it has no provider-intake acknowledgment because v3 never
recorded one. The live checkpoint lookup therefore excludes migrated-v3 gap
history. The bytes remain reopenable as historical evidence; NQ does not
silently promote them into an acknowledged v4 cursor.

The current live cursor is still the NQ-owned helper-protocol checkpoint bound
into the request and echoed in the raw response. Schema v4 does not claim a
separate provider-owned sequence protocol: both core and store reject a
nonempty `provider_sequence` for the local helper. Supporting such a sequence
would require a later provider contract that states its ordering and
acknowledgment law explicitly.

## Coarse health is not judgment

The public status model retains the existing coarse operational projection:
both `DetectorState::Present` and `DetectorState::ExplicitlyAbsent` may map to
`HealthState::Healthy`. Their codes and their complete
`EvaluationEnvelopeV2` values remain distinct and authoritative. Here,
`Healthy` means that the evaluation component successfully performed its
bounded purpose; it does not mean that the detector condition is absent.

`HealthState` is therefore a presentation and indexing projection only. It is
not an input to provider admission, provider intake, report admission,
testimonial sufficiency, acknowledgment, checkpoint advancement, or authority.
Consumers requiring detector meaning must use the exact typed evaluation
envelope rather than the coarse state.

## NQ/AG and JCP posture

This foundation does not add AG integration. Provider admission and helper
capability grants control NQ's own evidence-collection machinery; they do not
authorize external effects. The following lifts remain forbidden:

```text
AdmittedReport | Finding | Evaluation | ArchiveVerification
    ->/ Authorized<Action>

future MayTestifyFor<X>
    ->/ Authorized<X>
```

No action standing, operational budget, promotion, break glass, authority
burn, effect execution, or permission to act is introduced.

This foundation is also not JCP. It retains exact NQ-specific provider,
intake, refusal, evaluation, and custody types. It does not create generic
claim envelopes, semantic negotiation, a bridge registry, unresolved-frontier
wire objects, or shared AG/NQ protocol types. Common shapes may be reconsidered
only after a second concrete consumer creates real interoperability pressure.

## Deferred work and exact non-claims

The campaign establishes a semantic and custody foundation; it does not claim:

- that acquisition has been moved out of `nqd`;
- an independently deployed watcher or named monitoring product;
- a public, remote, network, fleet, queue, or POST intake surface;
- a universal plugin or provider system;
- eBPF, TPM/IMA, Git/build, formal-verifier, database, cloud, application,
  or human-inspection providers;
- provider self-authentication or trust in declared backend provenance;
- provider-owned admission, evaluation, health, testimony, or authority;
- generic claim-indexed entitlement or anti-entitlement;
- an unresolved-bridge protocol;
- JCP extraction or AG integration;
- modification or requalification of the tagged `v0.1.0` release.

Physical monitoring separation may be considered only after the local helper
proves this versioned boundary, exact replay law, atomic custody chain, durable
acknowledgment, schema migration, restart, backup, archive, and hostile
non-implication tests end to end.

## Qualified campaign identity

That bounded foundation is clean-pinned at candidate commit
`44e556709e629eb3c83d1d74bfbcf12cb4c9a549`, tree
`9aee37f90b93f27296550d9664af5ec574e5bf27`, with parent
`e3c451f9722cb81dd22af25c52b264e6b888ed81`. The clean-pinned admissibility
ledger passes all three active controls with zero obstructions or waivers and
2/2 semantic mutations biting. Rebuilt package SHA-256
`4f078257b2a23dd06f51ec3e2376b16973d247d0f0be9e6d14c6325f04d9408f`
passed fresh KVM qualification
`/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-22-44e5567`; all four mandatory
markers and the independently reopened exact 51-file evidence seal passed.

The post-release verdict is **READY-FOR-PROVIDER-INTAKE-RATIFICATION**. The
complete identity, test ledger, migration treatment, package digest, and VM
receipt are recorded in
[`../audit/receipts/run-2026-07-22-provider-intake-foundation/RECEIPT.md`](../audit/receipts/run-2026-07-22-provider-intake-foundation/RECEIPT.md).
This qualification does not alter or extend local tag `v0.1.0`, which remains
fixed at the earlier qualified release commit.

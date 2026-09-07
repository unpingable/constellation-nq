# Operator-beta systemd and HTTP observation contract v1

**Recorded:** 2026-09-07
**Status:** `M1B_NQ_NG_CONTRACT_REAUDIT_REQUIRED__IMPLEMENTATION_NOT_STARTED`

**Prior review:** NQ-ng subject
`a0b166eb5e7ff0d2d0a5074c2a284dc4c831d6f6` was
`NOT_ACCEPTED / CORRECTION_REQUIRED`; this non-rewriting child closes only
the bounded contract findings and carries no implementation acceptance.

**NQ-ng successor base:**
`d9c9f419283ec690014f706c5a6738451918f0f7`

**Accepted NQ-ng implementation subject inherited by that result:**
`78ba5137c83089d6f1cd2bada65f6f7bdda2669c`

**Qualified Monitor dependency:**
`b2d52fe34f146774cbf5601819982c267c7fb082`

**Accepted Docket composition contract:**
`2be939c744f5cbd94a9047b61e9322b23750c79a`

This contract replaces the classic-NQ implementation choice only for the
2026 operator-beta campaign. It does not declare a general NQ-ng cutover,
import classic findings, or inherit classic qualification. The classic lane
and its local test results remain historical evidence and are superseded for
this campaign.

## Governing ownership

NQ-ng owns compiled profile semantics, exact request/provider/profile/subject/
scope/vantage bindings, evidence admission, deterministic derivation, typed
refusal, immutable diagnostic artifacts, and query-only inspection/export.
An acquisition helper owns bounded testimony only. Nightshift owns recurrence
and temporal applicability across diagnostic occurrences. Docket and AG own
the separately qualified authority/effect history. No observation grants
authority and no enactment receipt proves a current postcondition.

NQ-ng's current north star requires application HTTP, generic systemd, and
remote reachability to remain distinct perspectives. Therefore this beta does
not add one aggregate service-health profile. It adds, if qualification accepts
the implementation, exactly two compiled diagnostic profiles:

1. `nq.systemd_unit/v1`, observed on the target VM from a `target_local`
   vantage; and
2. `nq.http_endpoint/v1`, observed on the controller VM from a
   `controller_http` vantage.

Each request executes one exact profile. Any conclusion that both required
postconditions are current belongs to a later Nightshift composition over the
two exact NQ artifacts. NQ must not emit `healthy`, `recovered`, `executed`, or
an equivalent aggregate.

## Exact beta subject and scopes

The two-VM fixture owner must retain one closed campaign-owned descriptor with
schema `constellation.operator_beta.service_subject.v1`. Its fields are exactly:

- `schema`;
- `campaign_id`, fixed to `constellation-operator-beta-2026`;
- `fixture_run_id`, the exact disposable-fixture occurrence;
- `target_machine_identity`, equal to the AG V2
  `systemd_machine_identity` for that occurrence;
- `unit_name`, fixed to `constellation-beta-http-fixture.service`; and
- `unit_file_sha256`, the exact installed unit-file byte digest.

The owner retains the RFC 8785 JCS bytes, byte length, plain SHA-256, and the
AG-compatible subject identity
`Digest::hash_domain("constellation/operator-beta/service-subject/v1", jcs_bytes)`
in the fixture manifest. AG proposal and Docket issuance/dispatch subject fields
must equal that domain-separated digest. Each NQ diagnostic
`DiagnosticSubjectV1.id` must equal its exact `sha256:` text. On every producer
and integration reopen, the descriptor bytes are reopened and the identity is
recomputed; equality of opaque strings without the retained preimage is
insufficient. A new fixture run, machine identity, unit name, or unit-file digest
creates a different subject. The campaign fixture owner owns these descriptor
bytes; NQ, AG, and Docket consume the identity without acquiring one another's
semantics.

The target-local systemd scope is a retained JCS descriptor with schema
`nq.operator_beta.systemd_unit_scope.v1`. It binds the common subject identity,
target machine identity, exact unit name and unit-file digest, systemd manager
interface `org.freedesktop.systemd1`, and the four observed properties
`LoadState`, `ActiveState`, `SubState`, and `UnitFileState`. The controller HTTP
scope is a separately retained JCS descriptor with schema
`nq.operator_beta.http_endpoint_scope.v1`. It binds the same subject identity,
the exact controller-vantage identity, literal `http://<fixture-address>:18080/healthz`
locator admitted by the fixture manifest, method `GET`, redirect policy
`refuse`, maximum response bytes, expected status `200`, and exact expected body
SHA-256. The literal address remains locator evidence, not the stable subject.

Each scope's NQ `SemanticIdentityV1` uses the schema string as `id`, `v1` as
`version`, and `nq_protocol::semantic_digest` over its retained JCS descriptor
as `digest`. Scope and vantage descriptor bytes, lengths, and digests are
fixture artifacts and must reopen before production or integration use.
Substitution of descriptor schema/domain, canonical bytes, machine, unit,
unit-file digest, fixture occurrence, controller vantage, endpoint, redirect
policy, bounds, expected status, or body digest must fail closed.

The later Nightshift-owned integration artifact records two independent
post-effect association edges:

```text
Docket attempt and terminal custody
  -> exact post-effect NQ systemd diagnostic artifact

Docket attempt and terminal custody
  -> exact post-effect NQ controller-HTTP diagnostic artifact
```

There is no systemd-artifact-to-HTTP-artifact predecessor edge. Each association
names its recording owner, exact Docket occurrence, exact NQ artifact identity,
and evidence reference. These are provenance links, not claims that Docket
caused the observed state. Matching target names, values, or times cannot create
an unrecorded edge.

## Exact questions, detectors, and freshness

The systemd profile key is exactly `{ id: "nq.systemd_unit", version: 1 }`.
Its question identity has id
`nq.operator_beta.systemd_unit_postcondition` and version `v1`; its detector
has id `nq.systemd_unit.postcondition` and version `1`; its stable condition
is `systemd_unit_postcondition_not_met`; and its primary claim is
`claim:systemd_unit_postcondition_not_met`. Its typed detector parameters are
the expected tuple `loaded`, `active`, `running`, `disabled`, plus the
subject and systemd-scope identities. With complete current typed evidence, any
tuple mismatch yields `present`; exact tuple equality yields
`explicitly_absent`. Missing, partial, stale, refused, or unprojectable evidence
yields `cannot_evaluate` and never absence.

The HTTP profile key is exactly `{ id: "nq.http_endpoint", version: 1 }`. Its
question identity has id `nq.operator_beta.http_endpoint_postcondition` and
version `v1`; its detector has id `nq.http_endpoint.postcondition` and
version `1`; its stable condition is
`http_endpoint_postcondition_not_met`; and its primary claim is
`claim:http_endpoint_postcondition_not_met`. Its typed detector parameters bind
the HTTP scope, status `200`, and the scope's exact expected body digest. A
complete bounded HTTP response with a status or body mismatch yields `present`;
exact status and body equality yields `explicitly_absent`. DNS, connect,
protocol, timeout, truncation, missing-body, stale, refused, or unprojectable
evidence yields `cannot_evaluate`, not a fabricated mismatch or absence.

Each question is a closed retained JCS descriptor with schema
`nq.operator_beta.diagnostic_question.v1`, its exact id/version, profile key,
profile digest, detector id/version/digest, condition, and scope identity. The
question's `SemanticIdentityV1.digest` is
`nq_protocol::semantic_digest` of those bytes. The ordinary compiled profile
and detector descriptors remain the existing
`nq.profile_descriptor.v1` and `nq.detector_descriptor.v1` contracts; their
digests are recomputed from canonical bytes. A question, detector, or profile
id without its matching retained descriptor digest grants no equivalence.

Both compiled profile descriptors fix `reliance_seconds = 60` and
`alignment_seconds = 0`. The zero alignment value means each detector consumes
one profile-local observation; it does not authorize cross-profile temporal
composition. NQ evaluation more than 60 seconds after the source observation,
or before it, yields `cannot_evaluate`; the exact 60-second boundary remains
inside the current NQ reliance window. Nightshift may impose a stricter
composition/current-support window over the two artifacts, but it may not
refresh their acquisition times or rewrite their historical NQ claims.
Profile, detector, question, scope, vantage, parameter, and freshness descriptor
bytes all participate in their existing NQ semantic identities.

## Required observations and bounded claims

The systemd observation retains at least:

- live machine identity;
- exact unit identity and manager/unit object references used;
- load state, active state, substate, and unit-file state;
- acquisition interval and clock qualification;
- exact helper/provider/build/profile identities; and
- raw and normalized evidence custody or an exact typed failure/refusal.

Its only determinate primary claim is the exact condition above, with the
existing NQ `present` or `explicitly_absent` polarity. It does not establish
controller reachability, application correctness, causation, or future state.

The HTTP observation retains at least:

- exact controller-vantage identity;
- literal endpoint locator as mutable locator evidence, separate from the
  stable service subject;
- method, redirect behavior, bounded response status and body/content evidence;
- DNS/connect/HTTP phase outcome where the implementation can distinguish it;
- acquisition interval and clock qualification;
- exact helper/provider/build/profile identities; and
- raw and normalized evidence custody or an exact typed failure/refusal.

Its only determinate primary claim is the exact condition above, with the
existing NQ `present` or `explicitly_absent` polarity. It does not establish
global reachability, service health, systemd state, effect causation, or future
state.

Missing evidence, no response, acquisition failure, profile refusal, stale
evidence, contradictory observations, and a valid observation of the undesired
state remain distinct. Process exit alone establishes none of these claims.

## Existing machinery reused

The implementation should reuse without semantic change:

- the static `nq-profiles` registry and compiled profile validation/evaluation;
- the canonical `nq-protocol` helper request/response exchange;
- existing admission, exact executable/configuration identity, bounded helper
  execution, provider-intake, and atomic collection custody;
- `nq.diagnostic_execution.v2`, including complete input accounting, exact
  subject/scope/vantage/profile/evaluator identities, clock qualification,
  limitations, nonclaims, and typed refusal;
- schema-v5 diagnostic-artifact custody and query-only
  `diagnostics inspect`/`diagnostics export`;
- FIELD-CLOCK's qualified Monitor operational record only where an exact
  campaign producer actually emits that record. Its library/example path is
  not treated as a deployed diagnostic or durable NQ store by itself; and
- NQ-ng packaging/admission patterns, without importing classic-NQ stores,
  verdicts, profiles, or migration assumptions.

Acquisition placement must follow the NQ-ng owner boundary. A helper may live
with NQ-ng for this deliberately narrow beta only if that is the smallest
package-correct first-party path. Otherwise acquisition belongs in the
existing witness owner and NQ-ng consumes the canonical helper protocol. The
contract does not authorize a new daemon, generic probe framework, dynamic
profile loader, or second evidence store.

## Concrete gaps at the admitted base

At `d9c9f419...`:

1. the static profile registry contains only `nq.conformance/v1` and
   `nq.host/v1`;
2. the only first-party live helper is the bounded local host helper;
3. live immutable diagnostic emission is sealed to the
   `nq.host/v1` load-pressure question;
4. no compiled generic systemd-unit or controller-vantage HTTP profile exists;
5. no package-qualified helper/provider path emits either required testimony;
6. FIELD-CLOCK operational qualification is a library/test/example surface,
   not a daemon/CLI-backed durable M1B execution path; and
7. no exact recorded NQ-ng postcondition edge is yet joined to the accepted
   Docket composition history.

The existing store, admission, refusal, inspection, export, and exact identity
machinery are reusable. The gaps above do not justify copying classic code or
creating another evaluator/state machine.

## Docket applicability

The accepted Docket contract remains applicable to authorization-independent
attempt/dispatch custody, executor binding, settlement, and same-attempt
reconciliation. None of those laws depends on classic NQ. Its current wording
does, however, name classic NQ as the postcondition owner. A non-rewriting
Docket documentation successor must replace only that final observation join
with these exact NQ-ng subjects/artifacts and receive independent re-audit.

Docket must not consume NQ evidence as standing, reinterpret NQ claims, or
copy NQ evidence into a Docket-owned truth record. NQ-ng must not treat a
Docket terminal outcome or AG executor receipt as observation evidence. The
complete M1 join is accepted only when an integration artifact cites the exact
Docket occurrence and exact fresh NQ-ng artifact identities without inferred
edges.

## Qualification gate

Before M1B can close, retain and independently qualify:

1. exact result-head ancestry from `d9c9f419...` and unchanged reopening of its
   inherited FIELD-CLOCK/SILICON artifacts;
2. exact compiled profile, detector, question, parameter, freshness, scope, and
   vantage descriptors and identities, plus helper/provider and package/binary
   identities;
3. fixture-owned service-subject bytes, length, plain digest, AG domain-separated
   digest, and recomputation by each consumer; substitute schema, domain,
   canonical bytes, fixture occurrence, machine, unit, and unit-file digest;
4. deterministic `present`, `explicitly_absent`, `cannot_evaluate`,
   missing, malformed, stale, no-response, timeout, and
   wrong-subject/scope/vantage fixtures for each exact condition;
5. direct substitutions of endpoint, redirect policy, response bound, expected
   status/body, profile, detector, question, parameter, freshness, provider,
   raw bytes, observation time, and clock qualification;
6. target-local systemd and controller-vantage HTTP observations on the exact
   disposable Debian 12 two-VM fixture, before and after one fresh governed
   effect occurrence;
7. the independent cross-profile matrix: systemd condition
   `explicitly_absent` while HTTP is `present` or `cannot_evaluate`; HTTP
   condition `explicitly_absent` while systemd is `present` or
   `cannot_evaluate`; both `present`; either stale; and both
   `explicitly_absent`, without an NQ aggregate verdict;
8. exact, independently recorded Docket-to-systemd and Docket-to-HTTP
   association edges, plus refusal to infer an absent edge or serialize one NQ
   artifact as the other's predecessor;
9. atomic diagnostic-artifact custody, restart-safe inspection/export, exact
   byte replay, and query-only reopening with no helper execution;
10. package install/remove/reinstall, store preservation, reset, and complete
    fixture teardown evidence;
11. explicit proof that no classic-NQ record or acceptance was imported; and
12. a terminal machine receipt that leaves whole-estate health, effect
    causation, authority, global reachability, Nightshift currentness, and
    production deployment unqualified.

The M1B owner result may qualify these two observations without claiming the
full AG/Docket/Nightshift chain. The composed M1 result is a separate later
gate.

## Current gate

This checkpoint is a contract-only correction. Runtime, schema, helper,
package, VM, service, and Docket changes remain `NOT_STARTED`. The next lawful
transition is independent re-audit of the exact non-rewriting contract child.
Acceptance may open bounded NQ-ng owner implementation; it does not qualify any
implementation or the composed M1 path. Classic NQ remains preserved but is
`SUPERSEDED_FOR_OPERATOR_BETA`; this contract authorizes no general NQ-ng
authority switch or production cutover.

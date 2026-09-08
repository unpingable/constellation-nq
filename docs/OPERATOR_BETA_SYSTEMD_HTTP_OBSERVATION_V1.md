# Operator-beta systemd and HTTP observation contract v1

**Recorded:** 2026-09-07
**Status:** `M1B_NQ_NG_IMPLEMENTATION_FOUNDATION_ACCEPTED_PROCEED`

**Review history:** subjects
`a0b166eb5e7ff0d2d0a5074c2a284dc4c831d6f6` and
`34d49dc1bdc42dc5f67c8a5c60eea11cd247f0bf` each returned
`NOT_ACCEPTED / CORRECTION_REQUIRED`. Subject
`8d6dca69e9171e6acdde3d3108d50a6a0f5db886` then returned
`ACCEPTED / PROCEED`. Acceptance covers this contract only; it carries no
runtime, package, VM, Docket-composition, or complete-M1 qualification.

Implementation subject `49486577b35f49c8227adf4693686a4ab4dc300b` returned
`NOT_ACCEPTED / CORRECTION_REQUIRED`: detector report selection lacked exact
instance filtering, public admission could bypass profile-owned policy validation,
and NQ could not reopen the fixture-owned service-subject preimage. Correction
`012c1898793f1f2755bb6f63c59a613b3c10f044` closed those findings but returned
`NOT_ACCEPTED / CORRECTION_REQUIRED` because public freshness evaluation could
consume caller-supplied policy bytes without proving equality to the active
admission. Correction `8c44da926300a4f5e1188be94881f15dc34aadbb` closes that
freshness custody path but returned `NOT_ACCEPTED / CORRECTION_REQUIRED` because
the normal CLI engine opener evaluated current policy semantics before authority
revocation, so an invalid policy could make revocation unreachable. Correction `28adb4deef034baf3ecc4207cee1482d21b3edcb` adds the one-shot
revocation custody path and returned `ACCEPTED / PROCEED`. It validates exact
configuration membership, store history, and authoritative binding without
consuming policy semantics. Acquisition and diagnostic production may proceed
under this accepted foundation; package, VM, and Docket composition remain held
for their separate gates.

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

The systemd request `ScopeBinding` has kind `systemd_unit`; its exact
`value` is a retained JCS object with schema
`nq.operator_beta.systemd_unit_scope.v1`, the common subject identity, target
machine identity, unit name and unit-file digest, manager interface
`org.freedesktop.systemd1`, and the requested properties `LoadState`,
`ActiveState`, `SubState`, and `UnitFileState`. The HTTP request
`ScopeBinding` has kind `http_endpoint`; its exact `value` is a separately
retained JCS object with schema `nq.operator_beta.http_endpoint_scope.v1`, the
common subject identity, controller-vantage identity, literal
`http://<fixture-address>:18080/healthz` locator admitted by the fixture
manifest, method `GET`, redirect policy `refuse`, and maximum response bytes.
The literal address remains locator evidence, not the stable subject. Expected
state, status, and body values are verdict policy and do not enter either scope.

NQ retains those objects as the exact request `scope.value`. The artifact's
`DiagnosticSubjectV1.scope` remains NQ's existing
`nq.diagnostic_scope.v1` semantic identity over the exact subject, complete
request scope binding, and profile identity. It must not be replaced by the
inner campaign scope digest. Vantage likewise remains NQ's existing
`nq.diagnostic_vantage.v1` identity over node, instance, declared vantage, and
provider. The fixture manifest retains the request scope/vantage configurations
and their canonical bytes; NQ recomputes its outer identities on reopen.
Substitution of inner schema/bytes, subject, machine, unit, unit-file digest,
fixture occurrence, controller vantage, endpoint, redirect policy, or response
bound must fail closed.

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
Its detector has id `nq.systemd_unit.postcondition`, version `1`, stable
condition `systemd_unit_postcondition_not_met`, and primary claim
`claim:systemd_unit_postcondition_not_met`. Its compiled typed parameters name
only the generic exact-four-field comparison law and the accepted external
policy schema; they contain no fixture, subject, scope, machine, unit, or
expected state.

The HTTP profile key is exactly `{ id: "nq.http_endpoint", version: 1 }`. Its
detector has id `nq.http_endpoint.postcondition`, version `1`, stable
condition `http_endpoint_postcondition_not_met`, and primary claim
`claim:http_endpoint_postcondition_not_met`. Its compiled typed parameters
name only the generic bounded status/body comparison law and the accepted
external policy schema; they contain no fixture, subject, scope, vantage,
locator, expected status, or body digest.

For each profile, the V2 `question` is exactly the detector descriptor
identity: detector id, decimal version, and canonical
`nq.detector_descriptor.v1` digest. There is no separate campaign question
descriptor and no scope-bearing question identity. Profile and detector
digests are recomputed from their existing canonical descriptors. Per-run data
must not rotate the compiled detector, question, cohort, or build identity.

Fixture-specific verdict inputs use the existing V2 `threshold_policy` field.
The fixture owner retains one immutable JCS policy per profile. Each policy
embeds the exact fixture-owned `constellation.operator_beta.service_subject.v1`
object as retained input so NQ can canonicalize it and recompute the AG-compatible
subject identity; this copy grants NQ no ownership of fixture or AG semantics. The systemd
policy schema is `nq.operator_beta.systemd_unit_threshold_policy.v1`; it binds
fixture run, common subject, complete request-scope identity, and expected
`LoadState=loaded`, `ActiveState=active`, `SubState=running`, and
`UnitFileState=disabled`. The HTTP policy schema is
`nq.operator_beta.http_endpoint_threshold_policy.v1`; it binds fixture run,
common subject, complete request-scope identity, expected status `200`, and
the exact expected body SHA-256 from the fixture manifest.

Each policy identity has stable id
`nq.systemd_unit.postcondition.threshold_policy` or
`nq.http_endpoint.postcondition.threshold_policy`, version equal to the exact
`fixture_run_id`, and digest equal to `nq_protocol::semantic_digest` over the
retained policy JCS bytes. Before evaluation, NQ must admit and reopen those
bytes, recompute the policy identity, require subject and request-scope
equality, and place that identity in `DiagnosticExecutionV2.threshold_policy`.
The detector disposition and artifact identity bind the policy. No evaluator
API accepts unbound expected values, and a policy substitution produces a
different result identity or fails closed. The base host-load producer's
detector-only threshold policy remains unchanged.

With complete current typed systemd evidence, any policy-tuple mismatch yields
`present`; exact tuple equality yields `explicitly_absent`. With a complete
bounded HTTP response, a policy status/body mismatch yields `present`; exact
status and body equality yields `explicitly_absent`. For either detector,
missing, partial, stale, refused, unprojectable, transport-incomplete, or
policy-unavailable evidence yields `cannot_evaluate` and never absence.

Both compiled profile descriptors fix `reliance_seconds = 60` and
`alignment_seconds = 0`. The zero alignment value means each detector consumes
one profile-local observation; it does not authorize cross-profile temporal
composition. NQ evaluation more than 60 seconds after the source observation,
or before it, yields `cannot_evaluate`; the exact 60-second boundary remains
inside the current NQ reliance window. Nightshift may impose a stricter
composition/current-support window over the two artifacts, but it may not
refresh their acquisition times or rewrite their historical NQ claims.
Profile, detector, question, scope, vantage, policy, parameter, and freshness
identities remain independently visible in the V2 artifact.

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

### Frozen beta acquisition placement and law

The smallest package-correct first-party path is one new, one-shot NQ-ng
binary named `nq-operator-beta-helper`. It implements only
`nq.systemd_unit/v1` and `nq.http_endpoint/v1` over the existing canonical
helper request/response protocol. It owns bounded acquisition testimony only:
it does not schedule, admit, evaluate, persist, retry, compose the two
profiles, or answer whether an effect occurred. It is installed as the same
exact package-owned bytes on both fixture VMs; the admitted watcher identity,
execution account, scope, vantage, and capability grant determine which one
of its two closed branches may run. `nq-host-helper` and `nq.host/v1` remain
unchanged.

For either branch the helper reads at most one request frame and accepts no
checkpoint. Strict framing, JSON, schema, protocol, deadline, and common-bound
validation occurs in canonical `nq_protocol::parse_request` before a request
exists that can safely be echoed. A malformed or common-invalid frame therefore
produces bounded stderr, no stdout response, and a nonzero process result, as
`nq-host-helper` already does. After strict parsing, the helper requires the
exact compiled profile descriptor digest and request binding and refuses any
capability other than the branch's one required capability. It emits exactly
one bounded report or refusal only when the negotiated response bound can
represent that exact echo and outcome. An otherwise valid request whose bound
cannot encode even the bounded fallback refusal instead produces no stdout and
a nonzero `UnrepresentableResponse` process result.

Both branches require `max_observations >= 1`, `max_coverage_entries >= 1`,
`max_payload_bytes >= 16384`, `max_report_errors >= 1`, and
`max_response_bytes >= 32768`. The helper emits exactly one coverage entry, at
most one observation, and at most one terminal structured collection error.
A valid request whose external read fails emits a `failed` report with
`unavailable` coverage, no observation, and that one bounded error. It never
converts absent testimony into a negative postcondition observation. Provider
intake retains the exact raw helper stdout separately from the validated
normalized report. Qualification fixes each accepted bound at its minimum and
exercises one-below-minimum refusal plus an unrepresentable-response case.

The systemd branch uses one direct zbus system-bus connection. On that same
connection and within the request's monotonic deadline it calls
`org.freedesktop.DBus.Peer.GetMachineId` on the systemd service and manager
object, then the read-only manager methods `ListUnitsByNames` for the one exact
unit name and `ListUnitFilesByPatterns` for that same exact name. The former
returns the exact unit object path plus `LoadState`, `ActiveState`, and
`SubState`; the latter returns the exact fragment path and `UnitFileState`.
Both replies must contain exactly one matching row. An alias/followed unit,
different unit name, or in-progress job refuses the stable observation cut.
This permits an installed inactive unit to be observed without calling the
authorization-bearing `RefUnit`, `LoadUnit`, or any mutation method. Those
exact service, object, and interface identities are compiled helper constants;
the scope's historical `manager_interface` value is an independently validated
binding value and is not misrepresented as the complete interface catalog.

The returned `FragmentPath` is opened as a regular file without following a
final-component symbolic link and read through the opened descriptor with an
exact 1048576-byte maximum. The helper computes its SHA-256 and requires both
the live machine identity and observed unit-file digest to equal the request
scope before emitting one complete observation. The normalized observation
retains the fixed manager object path, returned unit object path, exact four
state values, live machine identity, unit name, and observed unit-file digest.
Unit-list and unit-file-list failures are distinct; installed-but-inactive and
not initially loaded is a positive qualification case. Any connection,
machine, cardinality, identity, transition-state, list, file-open, file-type,
file-bound, digest, or deadline failure yields typed absence of testimony. The
helper performs no unit mutation and invokes no systemctl command.

The HTTP branch accepts only the exact beta shape already admitted by the
scope: plain `http`, method `GET`, redirect policy `refuse`, path `/healthz`,
port `18080`, no user information, fragment, or query, and a numeric fixture
address. It makes one bounded TCP connection from the declared controller
vantage, writes one HTTP/1.1 request with `Connection: close`, and follows no
redirect. The response must be one final HTTP/1.0 or HTTP/1.1 response with a
three-digit status, no interim response, no `Transfer-Encoding` header of any
value, and exactly one valid canonical-decimal `Content-Length` header. An
absent, duplicate, conflicting, signed, nondecimal, or noncanonical length is
invalid. EOF framing and chunked framing are not admitted in this beta. Every
header name must use the bounded ASCII field-name token syntax, and every
header value must contain only horizontal tab or visible ASCII bytes; malformed
unknown fields refuse just as malformed recognized fields do.

The complete header section including its terminator is limited to 16384 bytes.
The declared body length must not exceed the scope's `max_response_bytes`. The
helper reads exactly that many bytes and then requires connection EOF within
the existing request deadline. Premature EOF, a byte beyond `Content-Length`
regardless of TCP segmentation, or failure to establish bounded connection
closure refuses testimony. A complete response of any status, including a
redirect status, yields exactly one observation with status, exact body byte
count, and body SHA-256; detector policy, not the helper, decides whether that
observation meets the requested postcondition. Malformed framing, bound excess,
connect/write/read failure, or deadline expiry produces no observation. DNS is
not consulted in this beta and no current address is substituted for the
retained locator.

Every external operation is bounded by the request's existing Linux-boottime
deadline; no helper-local deadline may extend it. Direct library calls are
recorded as the package-owned helper implementation rather than inventing a
backend executable identity. The package/release manifests must name the exact
new binary before package qualification, but this contract checkpoint does not
itself build, install, activate, or qualify a package.

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
   not a daemon/CLI-backed durable M1B execution path;
7. current live V2 production derives `threshold_policy` only from the
   compiled detector and has no admitted external typed-policy input; and
8. no exact recorded NQ-ng postcondition edge is yet joined to the accepted
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
2. exact compiled profile/detector parameters and identities, V2 question
   equality to detector identity, profile freshness, NQ-derived outer scope and
   vantage identities, plus helper/provider and package/binary identities;
3. fixture-owned service-subject bytes, length, plain digest, AG domain-separated
   digest, and recomputation by each consumer; substitute schema, domain,
   canonical bytes, fixture occurrence, machine, unit, and unit-file digest;
4. exact immutable threshold-policy bytes, identity, admission, subject/scope
   binding, reopen, and disposition/artifact binding for each profile; every
   public collection/evaluation path validates the compiled watcher, while a
   freshness evaluation additionally reopens the exact active admission and
   proves policy equality before mutation; invalid and different-valid policy
   substitutions add no provider-intake, run, status, evaluation, or finding row;
   the CLI revocation path separately preserves exact config membership and
   binding/store custody without evaluating current policy, so an invalid policy
   cannot preserve active authority and revocation adds no provider, execution,
   evaluation, or finding testimony;
5. deterministic `present`, `explicitly_absent`, `cannot_evaluate`,
   missing, malformed, stale, no-response, timeout, and
   wrong-subject/scope/vantage/policy fixtures for each exact condition;
6. direct substitutions of endpoint, redirect policy, response bound, expected
   tuple/status/body, policy id/version/digest/bytes, profile, detector,
   question, compiled parameter, freshness, provider, raw bytes, observation
   time, and clock qualification;
7. target-local systemd and controller-vantage HTTP observations on the exact
   disposable Debian 12 two-VM fixture, before and after one fresh governed
   effect occurrence;
8. the independent cross-profile matrix: systemd condition
   `explicitly_absent` while HTTP is `present` or `cannot_evaluate`; HTTP
   condition `explicitly_absent` while systemd is `present` or
   `cannot_evaluate`; both `present`; either stale; and both
   `explicitly_absent`, without an NQ aggregate verdict;
9. exact, independently recorded Docket-to-systemd and Docket-to-HTTP
   association edges, plus refusal to infer an absent edge or serialize one NQ
   artifact as the other's predecessor;
10. atomic diagnostic-artifact and policy custody, restart-safe
    inspection/export, exact byte replay, and query-only reopening with no
    helper execution or policy reevaluation;
11. package install/remove/reinstall, store preservation, reset, and complete
    fixture teardown evidence;
12. explicit proof that no classic-NQ record or acceptance was imported; and
13. a terminal machine receipt that leaves whole-estate health, effect
    causation, authority, global reachability, Nightshift currentness, and
    production deployment unqualified.

The M1B owner result may qualify these two observations without claiming the
full AG/Docket/Nightshift chain. The composed M1 result is a separate later
gate.

## Current gate

Acquisition-contract subject `ff8fc80ab0dfc4cda10c6f525b2313c07125f482`
returned `NOT_ACCEPTED / CORRECTION_REQUIRED`. Its non-rewriting child
`e45c7b4bfb18ea740576a65f692b29f4390fbaff` returned
`ACCEPTED / PROCEED`.

Helper implementation subject `333d0bcc911245a1a137e9a124a61113b765e9bb`
is a direct non-rewriting child of that accepted contract. It passed the focused helper
suite, full locked workspace, warnings-denied workspace Clippy, formatting, owner boundary
gate, and deterministic negative control. Its separate qualification record is ready for
independent audit; no helper package, live system-bus, VM, provider-intake, Docket join, or
postcondition result is yet qualified.

The older profile/foundation runtime remains accepted through
`28adb4deef034baf3ecc4207cee1482d21b3edcb`. Docket composition remains a
separate later gate, now pinned through the main-loop accepted AG adoption reconciliation
without importing Docket or AG authority into NQ-ng. Classic NQ remains preserved but
`SUPERSEDED_FOR_OPERATOR_BETA`. This contract authorizes no general NQ-ng authority
switch or production cutover.

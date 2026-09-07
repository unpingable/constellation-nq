# Operator-beta systemd and HTTP observation contract v1

**Recorded:** 2026-09-07
**Status:** `M1B_NQ_NG_CONTRACT__IMPLEMENTATION_NOT_STARTED`

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

The campaign must retain one canonical service-subject descriptor containing
the exact target-machine identity and exact systemd unit identity. Its
domain-separated digest is the Docket/AG subject digest and is also exposed by
both NQ diagnostic artifacts as their exact logical subject identity. A
display hostname, unit label, URI, file path, timestamp, or matching prose may
not substitute for that descriptor.

The target-local systemd scope and controller HTTP scope are different exact
semantic identities. The systemd scope binds target machine, unit, systemd
manager interface, and the bounded state fields observed. The HTTP scope binds
the controller vantage identity, literal endpoint locator, method, redirect
policy, response bounds, expected status, and any exact body/content condition.
Both scopes reference the common service-subject identity. Neither scope may
be inferred from the other.

The composed qualification must record explicit predecessor/successor edges:

```text
Docket attempt and terminal custody
  -> exact post-effect NQ systemd diagnostic artifact
  -> exact post-effect NQ controller-HTTP diagnostic artifact
```

Those are integration evidence references, not claims that Docket caused the
observed state. Matching target names, payload values, or times cannot create
an unrecorded edge.

## Required observations and bounded claims

The systemd observation retains at least:

- live machine identity;
- exact unit identity and manager/unit object references used;
- load state, active state, substate, and unit-file state;
- acquisition interval and clock qualification;
- exact helper/provider/build/profile identities; and
- raw and normalized evidence custody or an exact typed failure/refusal.

It may support only profile-local propositions such as “this exact manager
reported this exact unit active/running at this observation cut.” It does not
establish controller reachability, application correctness, causation, or
future state.

The HTTP observation retains at least:

- exact controller-vantage identity;
- literal endpoint locator as mutable locator evidence, separate from the
  stable service subject;
- method, redirect behavior, bounded response status and body/content evidence;
- DNS/connect/HTTP phase outcome where the implementation can distinguish it;
- acquisition interval and clock qualification;
- exact helper/provider/build/profile identities; and
- raw and normalized evidence custody or an exact typed failure/refusal.

It may support only profile-local propositions such as “the bounded HTTP probe
from this controller vantage observed status 200 and the declared content at
this cut.” It does not establish global reachability, service health, systemd
state, effect causation, or future state.

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
2. exact compiled descriptors, profile semantic identities, detector/evaluator
   identities, helper/provider identities, and package/binary hashes;
3. deterministic positive, undesired-state, missing, malformed, stale,
   no-response, timeout, and wrong-subject/scope/vantage fixtures for both
   profiles;
4. direct substitutions of machine, unit, endpoint, subject, scope, vantage,
   profile, provider, raw bytes, observation time, and clock qualification;
5. target-local systemd and controller-vantage HTTP observations on the exact
   disposable Debian 12 two-VM fixture, before and after one fresh governed
   effect occurrence;
6. distinct outcomes for systemd-positive/HTTP-negative,
   systemd-negative/HTTP-positive, both negative, either missing, either stale,
   and both supported;
7. atomic diagnostic-artifact custody, restart-safe inspection/export, exact
   byte replay, and query-only reopening with no helper execution;
8. package install/remove/reinstall, store preservation, reset, and complete
   fixture teardown evidence;
9. explicit proof that no classic-NQ record or acceptance was imported; and
10. a terminal machine receipt that leaves whole-estate health, effect
    causation, authority, global reachability, Nightshift currentness, and
    production deployment unqualified.

The M1B owner result may qualify these two observations without claiming the
full AG/Docket/Nightshift chain. The composed M1 result is a separate later
gate.

## Current gate

This checkpoint is a contract only. Runtime, schema, helper, package, VM,
service, and Docket changes are `NOT_STARTED` until independent review accepts
the exact contract subject. Classic NQ remains preserved but is
`SUPERSEDED_FOR_OPERATOR_BETA`; this contract authorizes no general NQ-ng
authority switch or production cutover.

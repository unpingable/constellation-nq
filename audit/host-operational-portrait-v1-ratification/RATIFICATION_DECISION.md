# Host Operational Portrait v1 ratification decision

| Field | Value |
|---|---|
| Decision date | 2026-07-27 |
| Decision identity | `nq.host_operational_portrait.v1.ratification.2026-07-27` |
| Operator authority | explicit operator decisions R1.1 through R11.6, including amendments |
| Source commit | `6a336884ec9a4c4aeaa4dfe1ca78f7e893518341` |
| Source tree | `4ea26ea7562475a86281e6689b6ba644033ba231` |
| Frozen release | `v0.1.0` at `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d` |
| Specification status | `operator_ratified` |
| Subject-conformance status | `not_earned` for both subjects |
| Classic authority | unchanged |

## Binding verdicts

```text
HOST-OPERATIONAL-PORTRAIT-V1-SPECIFICATION-RATIFIED
R1-R11-OPERATOR-DECISIONS-RECORDED
SUSHI-K-PORTRAIT-V1-COMPLETENESS-NOT-EARNED
LABELWATCH-HOST-PORTRAIT-V1-COMPLETENESS-NOT-EARNED
CLASSIC-REPLACEMENT-NOT-AUTHORIZED
PARALLEL-QUALIFICATION-NOT-AUTHORIZED
CUTOVER-NOT-AUTHORIZED
RETIREMENT-EXECUTION-NOT-AUTHORIZED
BOUNDED-PORTRAIT-CLOSURE-UNIT-AUTHORIZED
```

Ratification makes Host Operational Portrait v1 the normative
replacement-completeness specification. It does not claim that either subject
currently satisfies the specification, that the required implementation
exists, that qualification has started, or that Classic authority has
changed.

The Stage 1 census and candidate records remain historical evidence. They did
not possess operator authority and are not rewritten. This decision, the
ratified portrait, policy ledger, and ratified manifest form the new decision
packet.

## Verdict separation

| Question | Verdict | Meaning |
|---|---|---|
| Is the Host Operational Portrait v1 specification normative? | **RATIFIED** | R1–R11 define the required contract and its nonclaims. |
| Does `sushi-k` satisfy it? | **NOT EARNED** | Required instantiated contracts, implementation, and qualification evidence are incomplete. |
| Does `labelwatch-host` satisfy it? | **NOT EARNED** | Required instantiated contracts, implementation, and qualification evidence are incomplete. |
| May NQ-NG replace Classic? | **NOT AUTHORIZED** | No parallel qualification, authority switch, deployment, or cutover follows from this decision. |
| May the next bounded closure unit proceed? | **AUTHORIZED WITH LIMITS** | Records, design, evidence gathering, and narrowly necessary implementation may close the five named blockers only. |

Specification ratification must never render as subject completeness.
Implementation completion must never render as qualification. Qualification
must never render as authority or cutover.

## Authority matrix

| Surface | Standing after this decision |
|---|---|
| Portrait v1 policy and requirement classifications | operator-ratified |
| Stage 1 observed facts | historical evidence, unchanged |
| `sushi-k` completeness | not earned |
| `labelwatch-host` completeness | not earned |
| General Stage 2 implementation | not authorized |
| Bounded blocker-closure work | authorized as stated below |
| Package publication, release, tag, or deployment | not authorized |
| Parallel qualification | not authorized |
| Classic or NQ-NG service mutation | not authorized |
| Portrait or notification authority switch | not authorized |
| Accepted retirement execution | not authorized |
| Human or AG action authorization | unchanged and separate |
| Docket execution | unchanged and requires separate authorization |

Every manifest row records implementation and retirement authority
independently. A `retirement_approved` classification is a conditional
successor-obligation disposition, not permission to stop, remove, purge,
delete, revoke, or mutate anything.

## Explicit closure blockers

The specification is ratified, but each affected subject remains incomplete
until the following identified artifacts are closed and qualified:

1. `B1.closed_subject_inventories`
   - versioned, closed `sushi-k` and `labelwatch-host` inventories;
   - explicit bounded membership rules and authoritative membership sources
     where exact enumeration is inappropriate;
   - explicit exclusions and the expected witness/provider/profile,
     privilege, namespace, and vantage for each required entry.
2. `B2.application_semantic_contracts`
   - frozen Labelwatch and Driftwatch native observation contracts;
   - profile questions, projections, state and phase maps, fields,
     denominators, freshness, threshold, hysteresis, recovery, and consumer
     contract identities;
   - exact separation of application testimony, NQ evaluation, and
     consumer-owned reliance.
3. `B3.production_namespace`
   - one unambiguous package, executable, service, configuration, state,
     socket, and documentation namespace;
   - no Debian `nq` package collision and no bare `/usr/bin/nq` production
     assumption.
4. `B4.sushi_k_platform_binding`
   - exact OS, architecture, glibc, kernel, systemd, sandbox, namespace,
     cgroup, socket, filesystem, and privilege facts needed to compare
     `sushi-k` with the ratified platform matrix.
5. `B5.external_vantage_identities`
   - exact required endpoint and outbound-dependency roles;
   - logical vantage identities and execution generations;
   - request context, topology evidence, consumer purpose, and qualification
     basis.

An open blocker remains `missing`, `not_configured`, `unsupported`, or another
applicable non-complete state. It cannot be omitted or treated as an implicit
exclusion.

## Authorized next unit

The next bounded unit is:

```text
HOST-OPERATIONAL-PORTRAIT-V1-BLOCKER-CLOSURE
```

It may:

- produce records, designs, schemas, typed contracts, decision packets, and
  conformance artifacts needed to close B1–B5;
- gather read-only deployment and application evidence needed to bind those
  artifacts;
- resolve the production namespace through an explicit operator decision;
- make narrowly necessary implementation changes whose only purpose is to
  produce or validate the ratifiable blocker-closure artifacts;
- add validators, fixtures, hostile vectors, canonical examples, and focused
  conformance tests for the closed artifacts; and
- conduct a focused conformance review against this already-ratified
  specification and update each subject's completeness verdict.

It may not:

- deploy or mutate a production host or service;
- start parallel Classic/NQ-NG qualification;
- switch portrait or notification authority;
- execute any approved retirement;
- publish a package, create or move a tag, create a release, or push;
- claim either subject complete without the complete focused conformance
  evidence;
- broaden into general Stage 2 implementation unrelated to B1–B5; or
- change NQ, Nightshift, consumer-reliance, notification, authorization, or
  retirement semantics merely to make a blocker easier to close.

Narrow implementation is authorized only when it is necessary to produce or
validate a blocker-closing artifact. The closure unit must identify that
dependency before changing code.

## Re-ratification law

Closing a deployment-specific inventory, implementing an already-required
contract, supplying qualification evidence, or updating a subject
completeness verdict does not require another R1–R11 convention.

Full policy re-ratification is required only when closure work proposes a
material change to the ratified specification, including a change to:

- ownership or authority boundaries;
- mandatory categories, subject or role scope, or outcome taxonomy;
- evidence, coverage, state-applicability, contradiction, coherence,
  reliance, recovery, or supersession law;
- recurrence, campaign, notification, retention, backup, or restore law;
- production support or installation contract;
- functional-equivalence, authority-switch, rollback, or retirement law; or
- another verdict-affecting normative requirement in the policy ledger.

If closure work discovers such a change, it must stop the affected work,
record the exact conflict, and request a focused amendment. Unaffected
decisions remain ratified.

## Adversarial-review conditions

The required semantic-authority review and operator-completeness review found
that current preview surfaces cannot be promoted as the target contract.
Accordingly:

- coarse NQ `HealthState`, retained finding “current condition,”
  `operator_work_state`, scheduler/notification preview kinds, and
  command-shaped `safe_next_checks` are non-normative;
- NQ evaluation-time sufficiency is not Nightshift current reliance;
- a first-ever refusal or `CannotEvaluate` cannot disappear through an empty
  findings view;
- an old semantic lineage cannot become current merely because it is the
  latest artifact in that lineage;
- recursive NQ dependencies require bounded acyclic ancestry and root-evidence
  deduplication;
- losing one side of a contradiction narrows coverage and does not resolve
  the contradiction;
- rollback eligibility cannot revive Classic authority, currency, or
  standing; and
- an agent proposal, Nightshift posture, notification receipt, or rendered
  endpoint cannot become diagnostic truth or action authority.

These findings constrain implementation and conformance. They do not undo
specification ratification.

## Nonclaims

This decision does not:

- bless current Classic topology or current NQ-NG DTOs as the target design;
- import Classic database state or findings into NQ-NG current truth;
- select a final production namespace;
- claim independent corroboration from package, process, provider, or vantage
  multiplicity;
- authorize arbitrary PromQL, runtime profiles, provider assertions, or agent
  interpretations as NQ evidence;
- authorize backup, remediation, notification, retirement, or Docket action;
- alter the frozen `v0.1.0` tag; or
- authorize a push, release, publication, deployment, or remote mutation.

# Host Operational Portrait v1 ratification — final report

## Outcome

Host Operational Portrait v1 is now the operator-ratified normative
replacement-completeness specification.

```text
HOST-OPERATIONAL-PORTRAIT-V1-SPECIFICATION-RATIFIED
SUSHI-K-PORTRAIT-V1-COMPLETENESS-NOT-EARNED
LABELWATCH-HOST-PORTRAIT-V1-COMPLETENESS-NOT-EARNED
CLASSIC-REPLACEMENT-NOT-AUTHORIZED
BOUNDED-PORTRAIT-CLOSURE-UNIT-AUTHORIZED
```

These are separate verdicts. Specification ratification is not subject
completeness. Subject completeness is not implementation completion.
Implementation or qualification is not authority or cutover.

## Repository state and scope

| Item | Value |
|---|---|
| Repository | `/home/jbeck/git/skunkworks/nq-ng` |
| Starting branch | `main` |
| Starting HEAD | `6a336884ec9a4c4aeaa4dfe1ca78f7e893518341` |
| Starting tree | `4ea26ea7562475a86281e6689b6ba644033ba231` |
| Starting worktree | clean |
| Frozen tag | `v0.1.0` → `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d` |
| Ending commit | the local decision commit containing this report; exact hash is reported by the final handoff |
| Push/release/deployment | none |

This was a policy and product-definition unit. It did not implement profiles,
witnesses, packages, Nightshift, Monitor, notifications, or application
overlays. It did not contact or mutate a production host. Classic and every
other repository remained read-only.

## Evidence reviewed

The review read the complete required Stage 1 corpus:

- [`docs/NORTH_STAR.md`](../../docs/NORTH_STAR.md)
- [`docs/SEQUENCING.md`](../../docs/SEQUENCING.md)
- [`docs/IMPLEMENTATION_STATUS.md`](../../docs/IMPLEMENTATION_STATUS.md)
- [`stage1-truth-and-qualification/FINAL_REPORT.md`](../stage1-truth-and-qualification/FINAL_REPORT.md)
- [`DEPLOYED_CAPABILITY_MANIFEST.json`](../stage1-truth-and-qualification/DEPLOYED_CAPABILITY_MANIFEST.json)
- [`HOST_OPERATIONAL_PORTRAIT_V1.md`](../stage1-truth-and-qualification/HOST_OPERATIONAL_PORTRAIT_V1.md)
- [`SUSHI_K_CENSUS.md`](../stage1-truth-and-qualification/SUSHI_K_CENSUS.md)
- [`LINODE_CENSUS.md`](../stage1-truth-and-qualification/LINODE_CENSUS.md)
- [`FRESH_OPERATOR_AUDIT.md`](../stage1-truth-and-qualification/FRESH_OPERATOR_AUDIT.md)
- [`OWNERSHIP_CORRECTION.md`](../stage1-truth-and-qualification/OWNERSHIP_CORRECTION.md)
- [`NOTIFICATION_FACET_CANDIDATE.md`](../stage1-truth-and-qualification/NOTIFICATION_FACET_CANDIDATE.md)

Relevant frozen Classic reconciliation, qualification, provider-intake,
system-contract, packaging, public-contract, and source records were inspected
when a policy decision depended on their exact current boundary.

Stage 1 evidence remains byte-identical. It is cited as historical evidence
and was not rewritten to imply authority it did not have.

## Operator decisions

The operator accepted R1.1 through R11.6 with amendments. The complete durable
result is [`POLICY_LEDGER.md`](POLICY_LEDGER.md).

R6.1–R6.6 appeared in the transcript as recommended backup/restore decisions
without a standalone intermediate “accept R6” line. The final operator
instruction explicitly declared all R1–R11 normative and ratified the complete
specification, thereby supplying the required operator authority for R6 rather
than leaving acceptance inferred from conversational sequence.

| Group | Ratified subject |
|---|---|
| R1 | logical subjects, closed inventories, complete host/workload vocabulary, substrate/scope separation |
| R2 | condition/recovery/supersession, identified thresholds, time/applicability, application semantic ownership |
| R3 | Labelwatch/Driftwatch and operator workflows, AG Classic/AG-NG separation, explicit exclusions |
| R4 | Nightshift recurrence/expiry/campaigns, alert intent, route roles, durable attempts, order/replay |
| R5 | retention classes, dependency closure, sensitive capture, Classic archive, fail-closed custody |
| R6 | backup scope, RPO/RTO, generations, verification, restore, zero-loss artifacts |
| R7 | external/outbound vantages, consumer-evaluated failure-domain separation, lineage deduplication |
| R8 | Ubuntu production matrix, non-colliding install contract, explicit roles, clean-install acceptance |
| R9 | NQ/Nightshift/inspector/frontend/access contracts and exact evolution law |
| R10 | isolated qualification, event/time gates, row-scoped reset, clean replacement, switch/rollback |
| R11 | conditional Classic/user-local/adapter/probe retirement and retained SMART obligation |

The final operator decision corrected the adversarial recommendation:

- the normative specification is ratified now;
- both subject instances remain incomplete;
- Classic replacement remains unauthorized; and
- the next bounded blocker-closure unit is authorized without repeating all
  policy ratification unless the contract materially changes.

## Records produced

| Record | Purpose |
|---|---|
| [`RATIFICATION_DECISION.md`](RATIFICATION_DECISION.md) | binding verdicts, authority matrix, blockers, next-unit scope, re-ratification law |
| [`POLICY_LEDGER.md`](POLICY_LEDGER.md) | normative R1–R11 decisions and amendments |
| [`HOST_OPERATIONAL_PORTRAIT_V1.md`](HOST_OPERATIONAL_PORTRAIT_V1.md) | integrated operator-facing specification |
| [`RATIFIED_CAPABILITY_MANIFEST.json`](RATIFIED_CAPABILITY_MANIFEST.json) | machine-readable 44-row classification and authority record |
| this report | audited campaign result and validation |

README, north-star, sequencing, and implementation-status pointers now expose
the ratified-specification/incomplete-instance split.

## Manifest transformation

The Stage 1 source manifest had authority `none` and mixed observed,
owner-decision, candidate-required, and candidate-retire axes. The new
manifest preserves every capability ID and each prior candidate
classification, then adds the ratified classification, rationale, affected
role, completeness consequence, implementation authority, retirement
authority, blocker links, and row-conformance status.

Canonical manifest SHA-256:
`99fb781d7039a0911c1b9e2064546cc2206bb2b1134aa682f8b21fdf0f35531a`.

| Ratified classification | Count |
|---|---:|
| `mandatory_core` | 15 |
| `deployment_required` | 7 |
| `operator_loop_required` | 12 |
| `conditionally_required` | 4 |
| `optional_supported` | 1 |
| `retirement_approved` | 5 |
| **Total** | **44** |

The single optional provider row is Labelwatch-host Prometheus/blackbox.
Underlying host, endpoint, outbound-dependency, and external-vantage questions
remain required and may be satisfied only by selected qualified providers.

The five retirement rows grant conditional disposition only:

- Classic runtime on both subjects;
- sushi-k user-local deployment shape;
- `governor-code-adapter`; and
- sushi-k's local Classic Monitor facade probe.

SMART retirement was rejected and is conditionally required per applicable
physical device/access path.

Sushi-k `telemetry.logs` remains `mandatory_core`: the Stage 1 row was a
candidate requirement, the ratified portrait requires an important-log/event
category, and no operator decision downgraded that category. The closed
inventory selects the exact sources. Zero configured sources remains
`not_configured`, not a satisfied inactive condition.

`retention.backup_restore` remains one of the 44 historical capability IDs but
has independent `retention.evidence_archive` and
`backup_restore.operational_state` subfacets. No combined healthy result is
allowed.

## Subject completeness

### `sushi-k`

Verdict: **NOT EARNED**.

Open focused blockers:

- B1 closed subject inventory;
- B3 final production namespace;
- B4 exact platform binding; and
- B5 required external-vantage identities.

This verdict also preserves every unimplemented or unqualified mandatory,
operator-loop, and activated conditional row. The current user-local Classic
deployment and local facade probe do not satisfy the successor contract.

### `labelwatch-host`

Verdict: **NOT EARNED**.

Open focused blockers:

- B1 closed subject inventory;
- B2 Labelwatch/Driftwatch semantic contracts;
- B3 final production namespace; and
- B5 required external-vantage identities.

The observed 14 services, storage paths, logs, and Prometheus families are
mandatory minima or provider evidence, not a closed successor inventory.

## Authorized closure unit

`HOST-OPERATIONAL-PORTRAIT-V1-BLOCKER-CLOSURE` may perform:

- records and design work;
- read-only evidence gathering;
- exact inventory/exclusion closure;
- application observation/profile/threshold contract closure;
- production namespace selection;
- sushi-k platform and external-vantage binding; and
- narrowly necessary implementation, validators, fixtures, vectors, and
  focused conformance work required to produce ratifiable closure artifacts.

It may not:

- deploy or mutate services;
- begin parallel qualification;
- switch authority;
- execute retirement;
- release, tag, publish, or push;
- claim a subject complete without focused conformance evidence; or
- broaden into unrelated general Stage 2 implementation.

A focused conformance review updates subject verdicts when blockers close.
Full R1–R11 ratification repeats only for a material specification change.

## Adversarial reviews

### Semantic laundering and accidental authority

The first review attacked current source and cross-component vocabulary. It
found that target law must not inherit:

- coarse NQ `HealthState`, where different exact detector states share one
  compatibility projection;
- finding “current condition” when a later refusal retains an older conclusive
  condition;
- empty findings as evidence of health;
- NQ `operator_work_state`, scheduler/notification preview kinds, or
  operational severity;
- free-text/command-shaped next checks as executable authority;
- evaluation-time sufficiency as current consumer reliance;
- recursive evidence without exact bounded acyclic ancestry and root
  deduplication; or
- Nightshift/agent/notification/projection artifacts as direct NQ evidence or
  action authority.

The decision and specification quarantine these surfaces. They remain
implementation-conformance risks, not ratified semantics.

### Operator completeness, sequencing, and architecture

The second review confirmed that the R1–R11 specification can be ratified
while both concrete subjects remain incomplete, provided those verdicts are
never merged. It identified exact inventories, application contracts,
production namespace, sushi-k platform, and external vantages as unresolved
instantiation/qualification obligations.

It also identified a potential conflict between externally supplied threshold
policy and the existing compiled-cohort rule. The ratified resolution is:
external policy is allowed only when typed, versioned, immutable,
custody/result-bound, and permitted by the compiled profile contract; changing
a cohort-sealed artifact changes the cohort identity.

The reviews found no basis for deployment, parallel qualification, cutover,
or subject-completeness claims.

The post-draft review produced four concrete checks:

- R4.1 expiry was tightened to say standing expires and cannot remain current
  130 seconds after the last admitted completion.
- R9.6 now requires a new schema for changed wire-field meaning, vocabulary,
  or interpretation; identity-only semantic evolution is limited to unchanged
  wire contracts.
- R6 authority was confirmed by the final explicit R1–R11 specification
  ratification rather than inferred from sequence.
- The proposed downgrade of sushi-k logs to conditional was rejected: the
  Stage 1 row was candidate-required, the ratified portrait makes important
  logs/events mandatory, and no operator decision downgraded it.

After those resolutions, both final packet reviews passed.

## Ownership and nonclaim audit

- Witnesses/providers own bounded acquisition, not diagnostic standing.
- NQ owns one scoped deterministic diagnostic and exact refusal.
- Nightshift owns recurrence, expiry, campaigns, transitions, and current
  cross-diagnostic posture.
- Frontends own presentation only.
- Agents own attributed interpretation/proposal only.
- Notification delivery owns attempt/outcome custody only.
- Consumers own reliance.
- Humans/AG own separate authorization.
- Docket owns governed execution after authorization.

No record claims that:

- package/process/provider count proves independence;
- producer evidence grants reliance;
- backup or notification status changes a host/application condition;
- Classic history is NQ-NG current state;
- a retirement disposition authorizes mutation;
- Prometheus is the source of truth;
- current deployment paths define product identity; or
- the frozen release tag changed.

## Validation

The final validation table is filled from the exact decision worktree before
commit.

| Gate | Result |
|---|---|
| JSON parse and canonical deterministic serialization | passed; sorted deterministic 44,878-byte JSON |
| 44-row identity/count/classification validation | passed; all source IDs and prior classes preserved |
| Markdown local-link validation | passed; 51 links across eight changed/new Markdown files |
| `git diff --check` | passed |
| `cargo fmt --all --check` | passed |
| documentation/manifest decision assertions | passed; authority split, blockers, retirement authority, source digest, and frozen tag checked |
| semantic-authority adversarial review | passed |
| operator-completeness adversarial review | passed |

The repository has no existing Host Operational Portrait decision-record
validator. The campaign therefore used deterministic JSON round-trip,
source-manifest cross-check, row-field/authority assertions, verdict-string
assertions, and local-link validation tailored to the changed records. No
executable semantics changed, so no product test result is claimed from this
records-only unit.

## Deviations

- The adversarial reviewers recommended withholding specification
  ratification until concrete inventories and contracts were instantiated.
  The operator explicitly separated normative specification ratification from
  subject conformance, ratified the specification, and kept both subjects
  incomplete. This report records the operator decision rather than silently
  adopting the recommendation.
- No binding prior production rename was found. The final namespace remains an
  explicit blocker rather than an invented name.
- The report cannot contain the SHA-1 of the commit that contains its own
  bytes. The final handoff reports that exact local commit.

## Final state

The decision is one local-main records unit. No push, fetch, tag, release,
publication, deployment, service mutation, retirement, qualification start,
or authority switch occurred. The frozen `v0.1.0` tag remains unchanged.

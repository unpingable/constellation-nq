# Host Operational Portrait v1

| Field | Value |
|---|---|
| Status | `operator_ratified_specification` |
| Version | 1 |
| Decision | [`RATIFICATION_DECISION.md`](RATIFICATION_DECISION.md) |
| Policy | [`POLICY_LEDGER.md`](POLICY_LEDGER.md) |
| Capability manifest | [`RATIFIED_CAPABILITY_MANIFEST.json`](RATIFIED_CAPABILITY_MANIFEST.json) |
| `sushi-k` conformance | `not_earned` |
| `labelwatch-host` conformance | `not_earned` |

Host Operational Portrait v1 is the normative first
replacement-completeness specification for the `sushi-k` and
`labelwatch-host` roles. It is a Nightshift operational portrait assembled
from exact bounded NQ diagnostics. It is not one NQ health verdict.

Ratification fixes required product categories, ownership, outcome law,
operator tasks, qualification meaning, and retirement/cutover boundaries. It
does not claim that an implementation or either subject instance satisfies
them.

## Product and authority stack

```text
witnesses and providers
  acquire bounded observations
        ↓
one scoped deterministic NQ diagnostic
  accounts for inputs
  checks custody, admission, coverage, and state applicability
  emits an exact disposition or refusal
        ↓
Nightshift diagnostic operations
  owns recurrence, expiry, campaigns, transitions, and current posture
        ↓
monitoring · alerting · operator portrait · reporting
        ↓
human or AG authorization
        ↓
Docket execution
```

The diagnostic profile and declared operational model are the engineered
artifacts. Diagnostics are what monitoring is built on.

NQ owns deterministic diagnostic derivation. Nightshift owns time and
cross-diagnostic operational posture. Frontends render the contracts. Agents
interpret only after deterministic derivation. Notification software delivers
identified alert intent. Docket executes only after separate authorization.

No ordinary-looking endpoint, rendered status, notification, agent statement,
or child disposition reconstructs another component's authority.

## Subjects, roles, and substrate

The v1 subjects are:

- logical `sushi-k`; and
- logical `labelwatch-host`.

Hostnames, DNS names, addresses, paths, container identities, and current
placement are locators or bound state, not logical subject identity.

Each subject has an explicit persistent role and a versioned closed inventory.
Inventory may enumerate members or use a bounded selector with an identified
authoritative membership source. Runtime discovery cannot silently create or
remove an obligation.

Deployment substrate is orthogonal to subject and vantage. A host role inside
a container satisfies host coverage only through explicit qualified host
namespace/resource attachments. Container start, host boot, workload attempt,
deployment generation, role, inventory, and vantage generation remain
distinct.

## Required outcome axes

Every required category exposes separate axes. A presentation may summarize
them but cannot collapse them.

### Coverage and acquisition

Allowed operator-facing outcomes include:

- `current`
- `partial`
- `stale`
- `refused`
- `missing`
- `unsupported`
- `intentionally_excluded`
- `not_configured`

`intentionally_excluded` requires an attributed ratified inventory rule.
`not_configured` does not satisfy a mandatory category.

### Bounded condition

- `condition_present`
- `explicitly_absent`
- `unknown`

Explicit absence requires sufficient current evidence under closed applicable
coverage. Silence, an empty vector, no finding, HTTP success, or process
liveness is not absence.

### Applicability and coherence

The portrait keeps distinct:

- acquisition freshness;
- state applicability;
- contradiction status;
- pairwise compatibility;
- joint coherence under an identified model;
- unresolved projection loss; and
- current Nightshift reliance under identified consumer policy.

Recent evidence may be state-incompatible. Pairwise agreement does not prove
one common state. Losing contradictory testimony narrows coverage; it does not
resolve the contradiction.

### Recurrence and delivery

Nightshift separately records:

- last requested slot;
- last admitted completion;
- next due slot;
- active, late, blocked, missed, or expired standing;
- campaign completion and success;
- transition and alert-intent state; and
- per-route notification configuration, qualification, attempt, and outcome.

Notification delivery cannot alter the underlying diagnostic.

## Input and dependency accounting

Every NQ diagnostic artifact accounts for:

- expected inputs;
- received inputs;
- admitted inputs;
- refused or invalid inputs;
- acquisition failures;
- exclusions and exact rationale;
- selected inputs; and
- the identified selection rule.

Each exported claim binds its own evidence dependencies and state identities.
One unstructured global state bag cannot imply co-occurrence.

Diagnostic artifact, request, execution, raw evidence, and normalized/projected
evidence have distinct identities. Same bytes or same deterministic result do
not collapse occurrence identity.

An incompatible structural change or a change to a wire field's meaning,
vocabulary, or interpretation requires a new schema version. A profile,
evaluator, threshold, projection, cohort, or canonicalization identity may
change evaluation semantics without changing schema only while the wire
contract and all field meanings remain unchanged.

Recursive NQ testimony is permitted only for the same exact parent diagnostic
question. It forms a bounded acyclic dependency graph with exact ancestry,
root-evidence identity, depth/fan-in bounds, cycle refusal, and transitive
deduplication. Projection limits, missing evidence, contradictions, and
consumer-owned reliance survive recursion.

Nightshift posture, agent interpretation, notification/import/projection
receipts, and consumer-reliance records cannot re-enter as direct NQ
observation.

## Recovery, supersession, and history

Recovery is a new immutable result for the same exact diagnostic lineage with
applicable continuing state and sufficient new evidence.

A change to subject, scope, vantage, required inventory, semantic/profile/
evaluator identity, boot, container, deployment, workflow attempt, or other
verdict-relevant generation supersedes the old result. It does not recover it.

The old artifact remains authentic and interpretable for its original bounded
state and time. It neither mutates nor becomes timeless truth.

Nightshift may expire or supersede current standing without changing the NQ
artifact. Receipt, custody, derivation, restore, or a newer wall-clock value
cannot refresh old evidence. Clock reversal cannot revive expiry.

## Mandatory portrait sections

### Base host facts

Every subject requires:

- logical identity, boot, kernel, uptime, and clock basis;
- CPU, load, and pressure;
- memory and swap;
- filesystem/mount inventory, bytes, inodes, read-only state, and
  backing-device identity;
- interfaces, routes, listeners, and resolver state;
- declared service, user-service, container, timer, cron, batch, and other
  workload lifecycle;
- deployment/configuration generation and pending restart/reboot;
- important bounded log/event inventory; and
- conditionally applicable physical-device testimony.

### Diagnostic and operator loop

Every subject also requires:

- closed expected inventory and explicit exclusions;
- observation currency and exact acquisition time;
- NQ/provider/helper/profile/store self-diagnosis;
- stable typed diagnostic read/export and inspector access;
- Nightshift recurrence, expiry, campaigns, immutable posture, and generated
  enterprise-console views;
- notification route and delivery standing;
- evidence retention/archive standing;
- operational backup/restore standing; and
- clean-install and lifecycle qualification.

These are mandatory completeness gates but are not all host conditions.

### Deployment-required application and storage overlays

`labelwatch-host` additionally requires:

- Labelwatch native progression, publication, coverage, and consumer
  testimony;
- Driftwatch native ingest, lag, loss, queue, storage, gate, and facts-export
  testimony;
- exact Driftwatch-to-Labelwatch bridge identity and usability contract;
- generic lifecycle/dependencies for retained AG Classic, PostgreSQL, Caddy,
  PDS, and other declared workloads while deployed;
- declared SQLite database/WAL and important-log inventories;
- shared-storage/device and backing-path evidence; and
- inbound endpoint and outbound dependency vantages required by consumer
  purpose.

AG Classic topology does not define AG-NG. Any AG-NG overlay is separately
specified from `agd`, `agctl`, `ag-providerd`, `ag-effectd`, and actual
product-native boundaries.

`sushi-k` additionally requires:

- exact declared application/workload overlays;
- important log sources as a mandatory host category;
- conditionally applicable SMART or equivalent physical-device testimony;
- any inventory-selected SQLite/WAL, ZFS, GPU, or other substrate overlays;
- required remotely consumed endpoints; and
- required outbound dependencies.

Absent optional configuration remains `not_configured`; it is not a mandatory
success. If the closed role inventory declares it required, the corresponding
overlay becomes a deployment requirement.

## Vantages and failure domains

Every verdict-relevant vantage binds logical identity, execution generation,
placement/provider/network/resolver/credential/topology state, exact request
context, acquisition interval, and clock uncertainty.

For each externally consumed operational Labelwatch-host endpoint role, the
default is two off-host vantages: an actual consumer path and one outside the
primary hosting/administrative domain. Sushi-k applies this rule to endpoint
roles it declares. Both subjects separately inventory required outbound
dependencies.

Multiple providers do not prove independence. The consumer may produce a
claim-relative `supported_separation_assessment` from retained topology and
dependency evidence. It cannot grant truth, reliance, or authorization.

## Threshold and application contract law

Every verdict-changing threshold/baseline policy is typed, versioned,
immutable for evaluation, custody-bound, and included in result identity.
Opening, clearing, hysteresis or explicit lack of hysteresis, units, window,
clock, freshness, missing/refused behavior, and baseline owner are explicit.

Application repositories own native observations and phase/state vocabulary.
NQ private cohorts own compiled validation, projection, and diagnostic
evaluation. Consumers own reliance.

The concrete Labelwatch and Driftwatch contracts remain blocker
`B2.application_semantic_contracts`; their absence is one reason neither
subject is complete.

## Retention and backup

The ratified default ordinary retention is:

- 30 days online for admitted evidence from acquisition; and
- one year for semantic artifacts from creation.

Open episode dependencies remain protected until closure/attributed
abandonment, after which the normal period begins. Archive pruning preserves
exact verdict-affecting dependency closure and passes retrieval/replay before
online deletion.

Backup defaults are:

- RPO no greater than one hour;
- RTO no greater than four hours;
- hourly verified off-host copies outside the primary storage failure domain;
- 48 hourly, 14 daily, and 12 monthly generations;
- daily complete recovery sets; and
- quarterly isolated timed restore qualification.

Retention/archive and operational backup/restore are independent subfacets.
Neither can make the other healthy. Restore creates a new operation and
deployment generation and starts Nightshift current posture expired/unknown
until fresh diagnostics complete.

Failed custody fails closed: no result is derived from evidence whose required
commit failed. Protected capacity must allow durable pressure/refusal and
coverage-loss reporting.

## Installation contract

Initial production platforms are Ubuntu 22.04 LTS amd64 and Ubuntu 24.04 LTS
amd64, each independently qualified with exact runtime floors.

Production packaging cannot use Debian's unrelated `nq` package name or a bare
`/usr/bin/nq`. The final namespace is blocker `B3.production_namespace`.

Package installation may create only service identity and empty layout. It
cannot silently initialize/migrate state, admit providers, select a role,
enable/start services, overwrite config, or claim completeness.

Core/fabric, host, and application-overlay roles are explicit and persistent.
Clean install, upgrade, rollback, removal, and explicit purge have separate
validated operations. The supported journey requires no developer checkout,
sibling repository, compiler, workstation cache, or undocumented knowledge.

Container and Kubernetes surfaces remain architecturally allowed but
unqualified for Portrait v1 production.

## Operator presentation

NQ's supported surface is a diagnostic execution inspector. Nightshift owns
the estate/operator console.

Typed contracts must generate:

- declared diagnostic design;
- realized deployment;
- provider → NQ → Nightshift topology;
- diagnosis → proposal/intent → human/AG → Docket authority flow;
- dependency and coverage graphs;
- run/episode/transition/notification lifecycle; and
- declared-versus-realized violations.

Every summary drills to immutable artifacts. A top-level presentation cannot
hide mandatory stale, missing, refused, unsupported, contradictory, partial,
or unconfigured categories behind healthy.

Current coarse NQ `HealthState`, finding “current condition,”
`operator_work_state`, scheduler/notification preview kinds, and
command-shaped safe-next-check strings are not this contract.

## Functional-equivalence and replacement gate

Qualification compares the same subject, bounded operator question,
applicable state/interval, expected coverage, operator conclusion, and required
notification behavior.

Classic schema, rows, IDs, names, config layout, internal APIs, prose,
severity labels, and quirks are not compatibility requirements. Each manifest
row has its own acceptance relation; there is no universal “stronger than
Classic” ordering.

Qualification requires at least 14 consecutive days per subject under one
frozen generation and the complete required event set. Before cutover,
Classic remains sole portrait and notification authority and NQ-NG is
isolated, non-authoritative, and unable to page production.

Authority switches atomically per subject only after all required rows pass
and a separate operator decision is recorded. No row-level hybrid authority
exists.

After a successful switch, Classic is stopped. A sealed non-running rollback
set remains eligible for 14 days. Rollback is a new authority switch with new
deployment generation and fresh observations; it cannot revive old standing.

None of qualification, cutover, rollback, or retirement execution is
authorized by this specification ratification.

## Approved successor retirements

Subject to R10/R11 prerequisites and a later separately authorized mutation:

- both Classic runtimes may retire with no successor compatibility
  obligation;
- sushi-k's mutable user-local deployment shape may retire;
- `governor-code-adapter` may retire without replacement; and
- the local Classic Monitor HTTP probe may retire without being called
  equivalent to the required typed self-diagnostics.

SMART retirement is rejected. Device-native testimony is conditionally
required per physical device and supported access path.

Retirement absence is an explicit inventory change, never recovery.

## Current conformance and authorized next unit

| Subject | Specification | Completeness | Principal blockers |
|---|---|---|---|
| `sushi-k` | ratified | not earned | B1, B3, B4, B5 plus unimplemented/unqualified required rows |
| `labelwatch-host` | ratified | not earned | B1, B2, B3, B5 plus unimplemented/unqualified required rows |

The only authorized next unit is the bounded blocker-closure unit in the
ratification decision. It may close B1–B5 and perform focused conformance
review. It cannot deploy, begin parallel qualification, switch authority,
execute retirement, or claim completeness without evidence.

Ordinary closure and conformance do not repeat R1–R11. A focused amendment is
required only when work materially changes this specification.

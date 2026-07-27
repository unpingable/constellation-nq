# NQ Classic to NQ-NG semantic crosswalk

This crosswalk compares authority and executable behavior, not names.

## Executive conclusion

NQ-NG is the cleaner successor architecture candidate. Classic's twenty-commit
line is a donor and evidence corpus, not a second completed architecture:

- NQ-NG already has the stronger acquisition, admission, custody, evaluator,
  publication, migration, packaging, and lifecycle boundaries.
- Classic retains broader operational collectors and a consumer-reliance
  concept that NQ-NG lacks.
- Classic's runtime/database/dashboard implementation must not be used as the
  compatibility substrate.
- Functional equivalence should be built as NQ-NG-native profiles, helpers,
  detectors, and narrowly defined semantic/operator surfaces.

This is a successor recommendation, not a cutover or release verdict.

## Acquisition and composition

### Concepts are related but distinct

| Term | Actual layer | Owns | Does not own |
|---|---|---|---|
| Classic pack | Mixed deployment/acquisition grouping | Check descriptor, check-specific config, acquisition implementation or plan, registry metadata | NQ decision law in principle, although its contract still couples several layers |
| NQ-NG helper | Acquisition executable | Bounded native observation and typed helper response | Scheduling, admission, normalization, evaluation, notification, decision |
| NQ-NG provider | Acquisition-source identity and custody boundary | NQ-derived live identity/admission, exact provider attempt, native outcome, raw bytes, durable intake acknowledgment | Profile validity, truth, finding state, action authority |
| NQ-NG profile | Compiled semantic contract | Vocabulary, binding law, coverage, basis, capabilities, freshness, cardinality, normalized validation, projections and compiled detector registry | Helper execution, deployment selection, transport |
| NQ-NG watcher config | Runtime composition seam | Explicit helper command, exact profile, subject/scope/vantage, capabilities, schedule/resources/checkpoint | New profile semantics or provider authority |
| Classic `nq-suite` | Planning-only selection document | Strict topology and selected feature/pack plan | Launch; every plan says `launch.available=false` |
| NQ-NG system contract | Authority-free system-scope compiler | System spec, ratified cut, observation and future Porter projection artifacts | Package selection, helper installation, watcher launch, runtime enablement |

The mapping is therefore:

```text
one Classic pack
    -> zero or more NQ-NG profile versions
    -> one or more bounded helpers/providers
    -> explicit watcher instances in deployment configuration
    -> profile-owned detectors and generic read DTOs
```

Availability in NQ-NG means that the exact compiled profile and compatible
helper artifact exist and can pass admission. Enablement means that an
operator explicitly configured and admitted a watcher. Merely compiling a
helper does not enable it.

### Decision

Do not introduce Classic's `nq-monitor-check` registry or `nq-suite` into
NQ-NG. They would create a second composition system and would move semantic
authority out of the compiled profile boundary.

For local providers, NQ-NG's current static profile registry plus explicit
watcher configuration is sufficient. A future installation manifest may list
available first-party profiles/helpers, but it must remain packaging metadata,
not a semantic or runtime plugin registry.

## Witness and admission

### Classic artifact

Classic `nq.witness.v1` is an open-typed immutable producer artifact with:

- identity/canonicalization;
- subject, scope and vantage declarations;
- observation/custody/provenance fields;
- projection limits; and
- structural validation.

Classic `nq.projection_receipt.v1` is a consumer-produced record that an
external projection was adopted or refused. Structural validation and
adoption do not establish occurrence or sufficiency.

### NQ-NG native chain

NQ-NG deliberately has no one-to-one “witness file.” Its live path is split:

```text
NQ-bound provider attempt
    -> exact native acquisition outcome and raw bytes
    -> strict helper response / EvidenceReport
    -> profile-normalized ValidatedReport or typed refusal
    -> admitted report
    -> exact EvaluationEnvelope / finding or CannotEvaluate
```

For native observation this is stronger than Classic's generic artifact:

- request echo and deadline/resource bounds;
- exact subject/scope/vantage/capability binding;
- current provider identity derived by NQ from executable and admission facts;
- raw byte custody before semantic interpretation;
- independently compiled profile/evaluator source closure;
- separate provider admission and report admission;
- atomic publication with an acknowledgment that means custody and canonical
  processing only.

`DurableIntakeAcknowledgment` is not a Classic projection receipt. It
acknowledges local provider-intake persistence; it does not adopt an external
projection or establish truth.

### Version collision

No NQ-NG artifact may be called `nq.witness.v1` merely because it carries
evidence. The same version string would conceal different authority:

| Artifact | What acceptance means |
|---|---|
| Classic `nq.witness.v1` | structurally valid declared artifact |
| NQ-NG protocol-valid `EvidenceReport` | candidate input correlated to an NQ request |
| NQ-NG admitted report | candidate passed one exact compiled profile contract |
| NQ-NG evaluation | one exact detector evaluated admitted evidence |
| NQ-NG finding | current projection of immutable evaluation/finding history |

Direct Classic-witness import cannot reconstruct an NQ-NG provider request,
execution identity, capability grant, profile admission, or evaluator context.
Static Classic/zab2nq material may later be retained as historical external
projection context or transformed through an explicitly versioned importer
with provenance and semantic-loss receipts. It must never enter as current
native observation.

### Gap

Provider-neutral/external intake is genuinely absent from NQ-NG. It is not
fixed by the local provider foundation and is not safe to synthesize by
deserializing Classic witness bytes. It is deferred until a real replacement
vertical requires it.

## Decision, refusal, standing, and reliance

| Concern | Classic | NQ-NG | Crosswalk |
|---|---|---|---|
| Operational detector state | Generic status/reason and finding machinery | Profile/detector/evaluator identities; exact evidence refs; `Present`, `ExplicitlyAbsent`, `CannotEvaluate`; watermarks | NQ-NG is stronger/cleaner |
| Refusal transport | General claim/refusal plus legacy carriers | Separate acquisition, provider, protocol, helper, profile and detector refusal planes retained end to end | Retain NQ-NG; use correspondence tests only |
| Finding resolution | Classic lifecycle | Only sufficient current `ExplicitlyAbsent` can resolve; refusal/stale evidence preserves prior state | Retain NQ-NG |
| Consumer purpose | Reliance profiles bind consumer and purpose | No general consumer-purpose layer | Genuine NQ-NG semantic gap |
| Reliance receipt | Request/outcome/supporting refs/receipt; no action authority | No equivalent | Implement NQ-NG-native only when a real consumer needs it |
| Standing/claims/inquiry | Partial Classic semantics and broader historical product behavior | Explicitly not implemented | Cutover requirement depends on actual deployed use; local evidence is unresolved |
| Action authority | Neither monitor finding nor provider grants it | Explicit negative boundary | No transfer |

The term “decision” in NQ-NG provider replay documentation means preserving
the exact stored admission/evaluation outcome. It is not a general disposition
or reliance law.

Classic's reliance concept is therefore not already present under another
name. If deployed Track-B, Docket, Continuity, or another consumer actually
depends on purpose-bound reliance, that is a cutover blocker. This survey does
not contact production and cannot establish that fact.

Do not map an NQ-NG “healthy,” visible, present, admitted, or acknowledged
state to Classic `AuthorizedReliance`. Do not copy the Classic `EvaluatedReceipt`
facade. A later slice must define a consumer contract against NQ-NG's exact
admitted/evaluated artifacts and preserve “no authority.”

## Runtime and persistence

| Boundary | Classic rewrite | NQ-NG | Decision |
|---|---|---|---|
| Startup | Binary-private serve/config paths | Explicit CLI/daemon configuration and admission lifecycle | NQ-NG |
| Collection | Concrete all-collectors composite path remains | Per-watcher exact helper/profile/provider path | NQ-NG |
| Raw custody | Mixed server/core/DB paths | Provider intake owns exact native outcome and bytes before interpretation | NQ-NG |
| Database | One 64-migration SQLite axis; private table and raw connection crossing | Exact schema v4, profile-neutral store API, strict fingerprint, bounded public projections | NQ-NG |
| Publication | Classic generation transaction | Atomic provider/run/raw/admission/evaluation/finding/status/ack transaction | NQ-NG |
| Ordering | Classic generations/times | Database report/evaluation/finding sequences plus exact watermarks | NQ-NG |
| Upgrade | Newer-schema refusal and compatibility preflight over Classic lineage | Runtime never migrates; exact v3 -> v4 explicit backup-first upgrade | NQ-NG implementation; historical breadth remains a gap |
| Recovery | Classic database behavior | Verified online backup/restore and self-verifying cold archive | NQ-NG |
| Parallel operation | Classic default paths | NQ-NG currently uses colliding `/etc/nq` and `/var/lib/nq/nq.db` examples | Must isolate configuration/state/service during qualification |

No Classic SQLite table, migration, raw connection, or runtime adapter should
enter NQ-NG. NQ-NG must never be pointed at a Classic database.

The path collision is operationally important: a parallel qualification must
use a separate VM/host or explicit NQ-NG-only config, database, admissions,
socket, helper-runtime directory, service identity and console address. Shared
paths would make rollback and evidence ownership ambiguous.

## Packaging and operation

NQ-NG is materially stronger:

- reproducible prebuilt tar and Debian artifacts;
- exact manifest, modes, digests and build identity;
- no package-time initialization, migration, enablement, start, overwrite, or
  purge;
- separate helper/service accounts;
- hostile install/reinstall/reboot/remove/purge/reinstall and tamper evidence;
- explicit backup, upgrade and archive workflows.

Classic contributes installation-research methodology, not a stronger product
installer. Its clean-room track found a missing release asset, source-build
dependence, occupied-port refusal, and no first monitored result.

NQ-NG still has material packaging gaps:

- the current provider-intake code is post-`v0.1.0`, untagged and unpublished;
- both minted and post-release artifacts report package version `0.1.0` despite
  different schemas/bytes;
- there is no remote or public artifact location;
- the VM first-run specimen uses the conformance helper and produces no
  operational detector result;
- exact package-to-package v3 -> v4 upgrade and rollback have not been run in
  the VM; and
- no literal-docs non-author clean-room trial exists.

## Operator/read-model behavior

Classic's portable contribution is a set of semantic requirements:

- say whether evidence is current, stale, missing, or conflicting;
- distinguish NQ component health from monitored-system state;
- expose observation basis, sample/coverage and exact evidence;
- preserve unknown and contradiction;
- provide limitations and safe next inspections;
- never branch generic presentation on producer/check IDs.

NQ-NG's `FindingSnapshotV3` and `StatusSnapshotV3` already carry much of the
semantic substrate: condition, visibility, freshness, basis, typed refusal,
summary, evidence references, limitations, safe next checks, times and origin.
Status and monitored findings are separate.

The current console is only escaped JSON in `<pre>` elements. It does not
provide Classic's task-first dashboard. Full Classic HTML/SQL loaders are
compatibility debt. A minimum cutover can use the CLI/API if operator
qualification proves the result understandable; a rich dashboard is deferred.

## Capability disposition summary

| Material Classic result | Class | NQ-NG action |
|---|:---:|---|
| Protocol leaf | B | retain NQ-NG protocol and correspondence invariants |
| Witness/artifact isolation | B | retain split provider/raw/profile/evaluation chain |
| External witness corpus | E | preserve immutable donor identity only |
| Disposition/refusal | B | retain typed NQ-NG refusal/evaluation path |
| Consumer-purpose reliance | C | later NQ-NG-native implementation if a real consumer requires it |
| Config/newer-schema refusal | B | retain NQ-NG |
| Host acquisition algorithms | D | bounded manual adaptation into an NQ-NG profile/helper |
| Storage acquisition algorithms | D | later per-profile/helper work |
| Labelwatch plan | G | implement only after real acquisition semantics are recovered |
| Check-pack registry/all-collectors | F | exclude |
| `nq-suite` planner | F | exclude |
| Generic operator semantic requirements | C | project from NQ-NG DTOs; do not port Classic renderer/SQL |
| Classic HTML/SQL/dashboard | F | exclude |
| Clean-room methodology | D | adapt to NQ-NG package flow |
| Raw install/operator corpus | E | correspondence/evidence only |
| Classic database/runtime | F | exclude |
| Full task-first dashboard and notifications | G | after minimum functional cut |

## Resolved relationships

- **Pack/provider/profile:** resolved as different layers; Classic pack is not
  an NQ-NG abstraction.
- **Witness/admission:** resolved as non-equivalent artifact chains with a
  dangerous version/authority collision.
- **Decision gap:** operational evaluation is stronger in NQ-NG; consumer
  reliance/standing is genuinely missing.
- **Runtime/store gap:** NQ-NG owns the target architecture; operational
  coverage, historical import policy, and current-release qualification remain.
- **Installation/operator gap:** product packaging is stronger in NQ-NG;
  literal non-author first useful operation and concise read presentation
  remain unearned.

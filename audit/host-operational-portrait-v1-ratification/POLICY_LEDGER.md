# Host Operational Portrait v1 operator policy ledger

Status: **operator-ratified**, 2026-07-27.

This ledger records the accepted R1.1–R11.6 decisions and amendments. It is
normative for Host Operational Portrait v1. It grants only the authority stated
in [`RATIFICATION_DECISION.md`](RATIFICATION_DECISION.md).

The Stage 1 census and candidate documents remain evidence. Where their
candidate language differs from this ledger, this ledger records the later
operator decision. An implementation ambiguity must refuse or request an
amendment; it must not choose a convenient interpretation.

## R1 — closed subject inventories

### R1.1 — subject identities

- The subjects are logical `sushi-k` and logical `labelwatch-host`.
- `labelwatch.neutral.zone`, static hostnames, IP addresses, paths, container
  placement, and current checkout locations are locators or observations, not
  logical subject identity.
- Rebinding a subject is an identified inventory and state-generation change.
  It cannot silently continue a prior diagnostic lineage.

### R1.2 — closed inventories and membership

- Each subject has a versioned closed inventory.
- Exact enumeration is preferred for stable known members.
- Containers, timers, interfaces, mounts, short-lived workloads, and similar
  domains may use versioned bounded membership rules or identified
  authoritative membership sources.
- Runtime discovery may populate a declared rule. It cannot invent an
  obligation, silently remove a disappeared member, or turn an open search
  into closed-world absence.
- Every required entry names its expected witness/provider/profile, privilege,
  namespace, and vantage.
- Every exclusion is explicit, attributed, versioned, and exposes its
  completeness consequence.
- The Stage 1 observed sets are mandatory minima and donor evidence. They are
  not closed inventories by themselves.

For `labelwatch-host`, the minimum observed set includes 14 declared services,
four configured SQLite paths including absent `facts_work.sqlite`, three WAL
targets, four journal sources, and the observed node/external-HTTP provider
families. For `sushi-k`, it includes the six declared service targets,
currently refused SMART testimony, and the retired local Classic facade probe.
These facts cannot be treated as exhaustive.

### R1.3 — category and workload closure

The mandatory base-host vocabulary includes:

- identity, boot epoch, kernel, uptime, and time basis;
- CPU, load, and pressure;
- memory and swap;
- filesystems, mount state, bytes, inodes, read-only state, and backing-device
  identity;
- interfaces, routes, listeners, and resolver/name-resolution state;
- declared workload lifecycle and recent generation changes; and
- important bounded log and event sources.

Workload lifecycle includes system and user services, containers, timers,
cron, one-shot or batch jobs, expected deployment/configuration generation,
and pending restart or reboot state.

The manifest keeps mandatory core categories, deployment-required overlays,
operator-loop requirements, conditionally required categories, optional
supported providers, and approved retirement dispositions distinct.
`not_configured` never satisfies a mandatory category.

Nightshift recurrence/expiry and notification delivery are mandatory for the
complete operator loop but are not host facts. External DNS/TLS/reachability
is governed by R7; backup and restore by R6.

### R1.4 — deployment substrate is not diagnostic scope

Bare metal, package, container, pod, VM, and appliance deployment are
orthogonal to subject and vantage.

A containerized NQ may be:

1. a core/fabric node that makes no host-completeness claim;
2. a container-role node whose subject is the container or workload; or
3. a host-role node only when explicit admitted witnesses cross the required
   host namespaces and resources under declared privileges.

Container deployment does not implicitly narrow or broaden scope. A host-role
deployment declares every host namespace, mount, device, socket, capability,
credential, and provider attachment used to acquire host evidence.

Deployment inventory includes image/build identity, container/orchestrator
identity, logical NQ node identity, placement, PID/mount/network/user/cgroup/
time namespace relationships, capabilities and LSM posture, host mounts,
sockets, devices, credentials, persistent custody volumes, restart/update
generation, and self-diagnosis of process and attachments.

Host boot, container restart, and pod reschedule are distinct state changes.
Host boot identity cannot be inferred from container start identity.

Affected manifest facets: both subjects' `coverage.expected_inventory`,
`host.*`, `service.lifecycle`, `storage.*`, `network.*`,
`self_diagnosis.nq`, and deployment/overlay rows.

## R2 — condition, thresholds, time, and semantic ownership

### R2.1 — condition, recovery, and supersession

- A condition clears only through a new immutable evaluation of the same
  bounded question with sufficient current evidence, closed applicable
  coverage, and satisfied contradiction and joint-coherence checks.
- Missing, stale, refused, unsupported, partial, or contradictory testimony
  cannot clear a condition.
- Recovery applies only to the same diagnostic lineage and an applicable
  continuation of the relevant state.
- A deployment generation, boot epoch, container identity, workflow attempt,
  subject binding, profile/evaluator semantics, scope, vantage generation,
  required inventory, or other verdict-relevant state change supersedes the
  prior result. It does not rewrite it as recovered.
- The old artifact remains authentic, immutable, and interpretable as the
  bounded conclusion produced for its original state and time. It is not a
  timeless truth claim.
- Nightshift may record supersession or loss of current applicability without
  mutating the NQ artifact.

### R2.2 — threshold and baseline identity

Every threshold table declares:

- units, observation window, time basis, and baseline owner;
- opening boundary and clearing boundary;
- hysteresis or an explicit statement that none exists;
- freshness and state-applicability requirements;
- treatment of missing, partial, refused, unsupported, contradictory, and
  insufficiently projected evidence; and
- the exact policy/profile identity used by the evaluation.

A verdict-changing change creates a new threshold-policy or profile-semantic
identity. It creates a new cohort/build only when a compiled profile catalog,
evaluator, or other cohort-sealed artifact changes.

Operator policy may remain external to the binary only when it is typed,
versioned, immutable for the evaluation, committed to custody, included in the
disposition identity, and permitted by the compiled profile contract. This
does not allow mutable configuration to alter compiled profile semantics
without an identified compatibility boundary.

Classic thresholds and current `nq.host/v1` behavior are comparison evidence,
not wholesale successor law.

### R2.3 — acquisition time and current applicability

- Acquisition time may be an interval and carries relevant clock uncertainty.
- Request, receipt, provider-query, transport, custody, derivation, and
  Nightshift-evaluation times remain distinct.
- Later receipt, transport, custody, or derivation cannot refresh source
  evidence.
- A monotonic timestamp is meaningful only with its boot or process epoch.
- “Current state” is an evaluated claim, not the sample with the newest wall
  clock.
- Clock reversal cannot revive expired standing.
- Nightshift may change current posture through expiry, missed recurrence, or
  supersession while the original NQ bytes and identity remain unchanged.

### R2.4 — application semantic ownership

- The Labelwatch or Driftwatch repository owns its native phase graph, state
  vocabulary, acquisition semantics, and emitted observation contract.
- The private NQ cohort owns compiled validation, projection, coverage, and
  diagnostic evaluation semantics.
- Every downstream consumer owns its own usability and reliance decision.
- Application testimony may support a consumer-usability question. It cannot
  declare that a downstream consumer is authorized to rely.
- Consumer contract, freshness, accepted projection, purpose, and reliance
  policy have separate identified artifacts.

The Labelwatch and Driftwatch semantic families are required. Their exact
observation contracts, fields, denominators, phase maps, threshold policies,
freshness, and consumer contracts remain blocker
`B2.application_semantic_contracts`.

Affected facets: all condition-bearing rows; especially
`application.labelwatch`, `application.driftwatch`, host pressure/capacity,
SQLite/WAL, logs, network, and `observation.currency`.

## R3 — required application and operator workflows

### R3.1–R3.3 — retained application workflows

- Labelwatch progression and publication testimony is required.
- Driftwatch ingest, lag, loss, queue, storage, gate, and export testimony is
  required.
- The Driftwatch-to-Labelwatch facts bridge is an exact producer/consumer
  contract. Missing or stale bridge testimony narrows coverage. The producer
  cannot grant consumer reliance.
- Generic service or container lifecycle, HTTP success, database-file
  presence, and Prometheus samples do not substitute for application-native
  progression.

### R3.4 — deployed AG Classic versus AG-NG

The observed legacy/application workload set includes AG Classic
`governor`, `gov-webui`, `governor-bridge`, `receipts-feed`, and
`governor-code-adapter` where configured, plus PostgreSQL, Caddy, PDS, and NQ
services.

Current AG-NG architecture is `agd`, `agctl`, `ag-providerd`, and
`ag-effectd`. It is not inferred from the Classic service set.

While AG Classic remains deployed:

- preserve explicit lifecycle and declared dependency coverage;
- require a dedicated semantic overlay only for a named retained operator
  decision;
- never treat Classic service health as AG-NG readiness;
- never carry Classic names or boundaries into an AG-NG overlay; and
- never make the current topology normative for future AG deployment.

Any future AG-NG overlay is separately defined from actual process, provider,
effect, session, receipt, and authority boundaries.
`governor-code-adapter` is disposed by R11.4.

### R3.5–R3.6 — supported operator journey and exclusions

The supported operator journey must allow:

- exact single-diagnostic inspection;
- Nightshift inspection of profile, last result, applicability, expiry,
  recurrence, and posture;
- drill-down to immutable NQ and Nightshift artifacts;
- historical inspection after recovery, supersession, and expiry; and
- task-capable frontend rendering without private-table reconstruction.

Docket, Continuity, general reliance, agents, and remediation are not
Portrait v1 completeness prerequisites. The architecture still preserves the
separate human/AG authorization to Docket execution boundary.

Agents enter after deterministic derivation. They cannot fill missing
evidence, erase refusal, overwrite an NQ result, become child testimony, or
authorize acquisition or action. A proposed next diagnostic is inert until an
identified authorized Nightshift campaign operation accepts it.

Affected facets: application rows, `service.lifecycle`,
`operator_surface.typed_contracts`, and `self_diagnosis.nq`.

## R4 — recurrence, transitions, and notification delivery

### R4.1 — recurrence, expiry, and campaign law

The inherited routine-host Portrait v1 policy is:

- nominal recurrence: 60 seconds;
- deterministic 0–10 second jitter derived from identified
  subject/profile/schedule policy and stable across worker restart;
- immutable schedule run-slot identity;
- invocation retry at approximately +10 and +30 seconds only for identified
  retryable invocation/acquisition failures; and
- current standing expires and must not remain current 130 seconds after the
  last admitted completion.

Retries remain attempts for the same slot. An NQ refusal, unsupported profile,
missing required evidence, contradiction, or successfully derived adverse
condition is a terminal diagnostic outcome, not an invocation failure.

Each profile declares a maximum execution budget. A later slot does not
silently overlap an active prior slot; Nightshift records it blocked, late, or
missed under identified policy. Slower or deeper profiles have separately
identified schedules and expiry.

Campaign complete and campaign successful are distinct. A later completion
may restore current Nightshift standing but cannot alter the earlier missed,
expired, or refused artifact.

### R4.2 — transitions and alert intent

Nightshift creates the immutable transition and alert-intent record before
maintenance, acknowledgment, suppression, or delivery policy is applied.
Suppression affects delivery, not whether the transition happened.

Alert-intent transitions include open/reopen, identified escalation, required
coverage loss, campaign failure, and recovery. Supersession remains distinct.

- Acknowledgment suppresses reminders for the acknowledged open episode. It
  does not suppress escalation, recovery, reopening, new coverage loss, or
  materially changed evidence without a separate attributed policy.
- The default is one reminder after 24 hours for an uninterrupted actionable,
  unacknowledged episode. Daily recurring reminders need separate policy.
- Actionability and severity come from identified operational policy, never a
  display color or mere diagnostic-condition presence.
- Maintenance preserves all transitions and applies an explicit catch-up
  policy to current state at window end.
- Every suppression is durable and states actor/policy, reason, and end.

### R4.3 — required route roles

Both Labelwatch-host Slack and Discord logical route roles remain required
until individually retired. Sushi-k requires at least one qualified
operator-owned route for Portrait v1 completeness.

Each route retains logical identity and generation, operator owner, transport
policy, qualification status, last current delivery diagnostic, and a
secret-reference identity outside ordinary policy records.

Configuration is not qualification. Labelwatch route success is complete only
when both roles are independently qualified or explicitly retired. One route
success with the other unavailable is partial route coverage. A manual
procedure may support a bounded qualification interval but is not permanent
route completeness. Endpoint rotation creates a new route generation and
requires renewed qualification.

### R4.4 — attempt and outcome law

At-least-once describes sender-side durable attempt behavior. It does not
prove a remote application or person received a message exactly once.

The Portrait v1 default is approximately five attempts at 0, 30 seconds,
2 minutes, 10 minutes, and 30 minutes, with a 10-second request timeout.
This is not universal transport law.

Require:

- durable next-attempt deadlines surviving worker restart;
- versioned retryable, terminal, rate-limited, and ambiguous outcome policy;
- bounded provider retry guidance such as `Retry-After`;
- idempotency `(alert_intent_id, route_id)` and remote idempotency keys where
  supported, without an exactly-once claim;
- separate `transport_rejected`, `attempts_exhausted_without_acceptance`, and
  `ambiguous_possible_acceptance` terminal states; and
- exact per-route outcomes even when another route succeeds.

Notification delivery affects a separate notification-coverage diagnostic and
Nightshift notification posture. It cannot change the host or application
diagnostic.

### R4.5 — order, replay, and receipts

- Preserve the complete immutable transition order.
- Every outbound payload names transition sequence and current-state
  applicability.
- An older retried opening must not arrive after recovery as though it were
  current.
- A later transition may include identities and summaries of earlier
  undelivered or ambiguous transitions.
- Batching is allowed only if every constituent transition identity remains
  inspectable; coalescing cannot erase open, escalation, recovery, or
  supersession.
- Delivery gaps and ambiguous prior attempts remain visible.
- Recovery is not discarded because its opening delivery failed.
- Retain exact redacted rendered payload commitments and bounded response
  evidence sufficient for replay/audit, excluding endpoint secrets and
  unbounded sensitive bodies.
- Ordinary restart resumes the same committed schedule.
- Restore, rollback, cutover, and policy replacement require a new manual
  replay identity.

Affected facets: both subjects' `observation.currency`,
`notification.delivery`, `self_diagnosis.nq`, typed operator surfaces, and
Nightshift operator-loop obligations.

## R5 — retention, archive, and custody budgets

### R5.1 — retention classes

Default minimum ordinary retention is:

- 30 days online for admitted acquisition/evidence material, beginning at
  acquisition; and
- one year for ordinary semantic artifacts, beginning at artifact creation.

For a nonterminal episode, preserve the exact dependency closure and
transition history needed to audit that episode until terminal closure or
attributed abandonment; then begin the applicable period. This does not retain
unrelated recurring samples forever.

Legal, incident, qualification, and operator holds are identified, attributed,
scoped, and removable. A shorter security/privacy/source-policy exception must
be explicitly ratified and exposed as reduced evidence availability; dependent
artifacts cannot claim full replayability.

`online` means directly queryable through a supported product surface.
Archived-but-retrievable is a separate availability mode.

### R5.2 — dependency-preserving pruning

Deterministic reevaluation requires exact bytes or durable retrieval for:

- admitted evidence and normalization/projection inputs;
- schemas and canonicalization rules;
- profile catalog and evaluator;
- threshold/baseline policy;
- relevant cohort/build artifacts; and
- every other verdict-affecting dependency.

Before pruning, seal and verify an archive manifest, perform a bounded
retrieval/replay specimen, commit the archive result and prune receipt
transactionally, and mark all references with the resulting availability
mode. Shared roots are reference-counted across dependents.

Reevaluation means evaluation of the same retained evidence under the same
identified semantics. It is not reacquisition or proof that the result remains
current.

### R5.3 — sensitive provider and notification material

Redaction or bounded capture happens at the earliest governed boundary.
Endpoint secrets and unnecessary sensitive bytes must not first enter the
ordinary raw store.

Retain the exact admitted post-transformation bytes, transformation
policy/version, indication that transformation occurred, and bounded material
needed to audit rendering, route generation, sequence, and outcome. When exact
rendering matters, retain the exact redacted rendered payload, not only a
digest.

Every retained class declares sensitivity and access policy. Required
encryption keys and credential-reference lifetimes cover the evidence
retention life.

### R5.4 — Classic historical archive

Classic becomes one identified sealed cutover snapshot, not current truth. It
includes acquisition time/method, exact checksums and manifest, WAL-consistent
database state, inspection tooling, secret references rather than copied
secrets, and known replay/interpretation limits.

Any later Classic snapshot is a separate historical artifact. It cannot
replace the cutover snapshot or enter NQ-NG current state.

### R5.5 — budget exhaustion and fail-closed custody

- No NQ evaluation or disposition is derived when required custody commit
  fails.
- Store pressure cannot justify evaluating transient bytes and keeping only a
  conclusion.
- Nightshift posture expires or narrows when new evidence cannot be retained.
- Reserve protected capacity or an out-of-band durable path for pressure
  diagnostics, write-refusal receipts, archive/prune failure, and the
  resulting coverage-loss transitions.
- Sizing includes ordinary rate, bounded bursts, open-episode holds, archive
  lag, retry material, and safety margin.
- A deployment unable to meet retention is not Portrait-complete.

`retention.backup_restore` retains one manifest row for historical continuity
but contains separately evaluated `retention.evidence_archive` and
`backup_restore.operational_state` subfacets. They cannot yield one combined
healthy result.

Affected facets: both `retention.backup_restore`,
`notification.delivery`, `self_diagnosis.nq`, and all retained dependency
closures.

## R6 — backup and restore objectives

### R6.1 — protected scope

Backup standing covers:

- NQ custody, admission, evaluation, disposition, refusal, and policy state;
- Nightshift schedules, slots, campaigns, transitions, posture, and alert
  intents;
- notification routes, generations, queues, attempts, and receipts;
- exact release, profile/cohort, evaluator, configuration, and admission
  material; and
- every deployment-required persistent workload dataset.

Ephemeral/reproducible data is excluded only by an explicit application-owned
declaration with rebuild procedure and recovery consequence. NQ diagnoses
backup standing; it neither authorizes nor executes backup.

### R6.2 — recovery objectives

Portrait v1 defaults:

- RPO no greater than one hour of accepted operational state or required
  persistent workload data;
- RTO no greater than four hours to restore the declared role enough to
  acquire new evidence and expose retained history;
- at least hourly verified backup to a named off-host destination outside the
  primary storage failure domain;
- success only after remote copy and manifest commit/verification; and
- one daily complete recovery set including state, exact software/checksums,
  configuration, policies, profiles/cohorts, admissions, and resolvable secret
  references.

An application exception is identified, application-owned, and visible in the
portrait.

### R6.3 — generations

Retain 48 hourly, 14 daily, and 12 monthly operational generations. Take a
synchronous verified pre-change recovery artifact before upgrade, cutover,
authority switch, or destructive state maintenance. These generations are
separate from R5 evidence/archive retention.

### R6.4 — verification and restore qualification

Every backup passes checksum/manifest, schema/exact-version compatibility, and
semantic reopening with supported tooling.

At least quarterly, perform a timed restore into an isolated empty environment
and prove exact identity/configuration recovery, retained-artifact reads,
fresh acquisition without treating restored observations as current, RPO/RTO,
and notification-backlog reconciliation without automatic replay.
A checksum-only copy is not restore qualification.

### R6.5 — restore semantics

Every restore has a restore-operation identity and new deployment generation.
It cannot refresh evidence, render last disposition current, merge Classic and
NQ-NG, silently rebind a subject, reuse boot/container/process/route/placement
identity, or deliver restored notification backlog automatically.

Nightshift starts with historical context but expired/unknown current posture
until new applicable diagnostics complete. Notification replay follows R4.5.

### R6.6 — zero-accepted-loss artifacts

Ratification records, release/cutover manifests, authority-switch records,
frozen Classic snapshots, and rollback identities require two verified copies
in declared separate failure domains before reliance or switch. Sensitive
backups remain decryptable for their retention life without endpoint secrets
in ordinary manifests.

Backup failure affects backup coverage and Nightshift posture, not the
underlying host/application condition.

Affected facets: both `retention.backup_restore`, application/storage overlays,
and operator-loop posture.

## R7 — external vantages and failure-domain claims

### R7.1 — qualified vantage identity

A logical vantage identity is distinct from execution generation. Placement,
provider, network, resolver, credential, or topology change creates a new
generation and invalidates prior assumptions.

The request identity binds all verdict-relevant protocol context: scheme,
protocol, address/port, DNS name, SNI/Host authority, method or operation,
authentication context, and relevant proxy/CDN path.

Provider receipt, query, and transport completion do not substitute for
acquisition time or endpoint-state applicability.

### R7.2 — Labelwatch-host

Each externally consumed operational endpoint role requires two declared
off-host vantages by default:

- at least one represents an actual consumer path; and
- at least one lies outside the primary hosting or administrative failure
  domain.

Coverage is by endpoint role and consumer purpose, not necessarily every URL.
Two probes do not prove independence. Generic HTTP success cannot satisfy
content, identity, progression, or freshness requirements. Inability to obtain
two adequately separated vantages yields reduced external coverage.

Required outbound dependencies for Labelwatch, Driftwatch, Nightshift,
notification delivery, and retained workloads are separately identified by
purpose, resolver, route, credential, protocol, subject-side testimony,
expected remote behavior, provider/consumer evidence, and shared
failure/control domains. Inbound reachability and outbound usability are
different questions.

### R7.3 — sushi-k

Apply the same distinction to remotely consumed sushi-k endpoints and required
outbound dependencies. `no_external_endpoint_required` excludes only inbound
consumer endpoints; it does not exclude DNS, packages, APIs, notification,
authentication, or other outbound dependencies.

Container-local, same-host, and host-network observations retain exact
vantage. Targeting a published address does not turn them into LAN or external
testimony.

### R7.4 — supported separation assessment

Use `failure_domain_evidence` and
`supported_separation_assessment` until a qualified warrant evaluator exists.
The assessment is produced or accepted by the diagnostic consumer under an
identified evaluator/policy, claim-relative, purpose-bound, based on retained
topology/dependency evidence, and non-transitive.

A provider may testify about placement and dependencies. It cannot
authoritatively declare `independent: true`. The supported result is:

> Separation supported for claim C under topology T, failure vocabulary V,
> and interval I.

The assessment cannot upgrade observations into truth, reliance, or action
authority.

### R7.5 — ancestry, absence, and coherence

- Corroboration deduplicates transitive evidence lineage, not just immediate
  providers.
- Recursive ancestry is bounded and cycle-checked.
- Shared recording rules, federated series, caches, proxies, relays, and
  normalized derivatives remain one root when derived from one observation.
- Missing ancestry blocks an independence claim.
- A failed operation establishes failure from that vantage during its
  acquisition interval only.
- Endpoint-wide or subject-wide failure requires the corresponding closed
  coverage.
- Joint coherence requires an identified consistency model and evaluator.
  Agreement among valid views does not prove one common world state.

Affected facets: both `network.interfaces_routes_listeners_reachability`,
`coverage.expected_inventory`, application dependency rows, and the optional
Prometheus provider row.

## R8 — platform and installation contract

### R8.1 — production platform matrix

Initial production support is Ubuntu 22.04 LTS amd64 and Ubuntu 24.04 LTS
amd64. Each release qualifies independently from a clean install.

Qualification records architecture, glibc boundary, minimum kernel/systemd
features, and sandbox/namespace/cgroup/socket/filesystem/privilege
assumptions. Ubuntu 24.04 success does not imply 22.04 support.

Sushi-k's exact platform and capabilities must be bound before replacement
qualification. If outside the matrix, it requires a separately executed gate.

### R8.2 — production installation and naming

The production package and executable surface cannot use Debian's unrelated
`nq` package name or install a bare `/usr/bin/nq`. Collision detection is not
the normal solution.

Historical review found no binding alternate production rename. Therefore the
package, executable, service, configuration, state, socket, and documentation
namespace remains blocker `B3.production_namespace`.

The first-party workflow is documented, mechanically validated, idempotent,
inspectable before mutation, repeatable without source checkout, and
reversible where possible.

Package installation may create a service identity and empty layout. It cannot
silently initialize or migrate state, admit a helper/provider, select a role,
enable/start a service, overwrite configuration, or claim host completeness.
Configuration, initialization, admission, role activation, enablement, and
startup are explicit supported operations.

### R8.3 — roles

Core/fabric, host, and application-overlay roles are explicit, persistent, and
visible. Package installation does not silently select a role.

A role transition records old/new role, inventory consequences,
profile/cohort changes, privilege/namespace changes, validation, and rollback.
Host role requires the complete ratified provider/profile inventory.
Adjacency or shared placement proves neither coverage nor independence.
Application overlays are separately packaged and application-owned with
explicit private cohort compatibility.

### R8.4 — other surfaces

All supported artifacts use the same production namespace. Trial/tarball
surfaces cannot reintroduce bare `nq` as the assumed service interface.

No-root trial/conformance cannot establish host namespace coverage,
privileged provider availability, durable recurrence, lifecycle, backup
standing, or production completeness.

Container/Kubernetes deployments are architecturally allowed but unsupported
for Portrait v1 production until separately qualified for subject/vantage,
attachments, privilege, persistence, placement, image/deployment identity,
upgrade/rollback, and host evidence. User-authored configuration management is
not supported integration without its own qualification.

### R8.5 — clean-install acceptance

Qualification proves:

- coexistence with Debian's unrelated package and no package/path/diversion/
  alternative collision;
- consistent production names in help, docs, errors, and commands;
- a first truthful bounded portrait through supported CLI/API, without a false
  completeness claim;
- identity-preserving or explicitly transforming upgrade/rollback, with
  unsafe rollback refusal;
- removal preserving state/configuration by default and explicit,
  previewable, separately authorized purge; and
- no workstation cache, credentials, compiler, checkout, sibling repository,
  mutable external build directory, or undocumented knowledge.

Clean install does not itself satisfy enterprise console, notification,
parallel qualification, or cutover.

Affected facets: both `deployment.clean_install`, role/inventory facets, and
operator surfaces.

## R9 — typed product contracts and access

### R9.1 — NQ diagnostic execution

One bounded diagnostic produces one immutable artifact. It accounts for:

- expected, received, admitted, refused/invalid, and acquisition-failed
  inputs;
- excluded inputs with exact rationale;
- selected inputs and the identified selection rule; and
- per-claim evidence dependencies and state bindings.

A producer-selected frontier alone is insufficient. Excluding contradictory
required evidence narrows or blocks a claim; it cannot improve the denominator.
`intentionally_excluded` comes only from an independently ratified scope rule;
`unsupported` is an NQ/profile result, not a helper grant.

Distinguish diagnostic-artifact, request, run, raw-evidence, and
normalized/projected-evidence identities. Deterministic reproduction does not
collapse occurrence identities.

Profile severity is only bounded diagnostic-condition severity. It is not
Nightshift actionability, page priority, reliance, or authorization.
Safe-next-check output is identified deterministic output or clearly advisory
metadata. It does not execute acquisition.

### R9.2 — Nightshift operational posture

An immutable posture snapshot binds:

- exact Nightshift build and policy;
- snapshot/posture generation;
- subject, role, diagnostic inventory, recurrence, and expiry;
- mandatory, optional, excluded, and unsupported categories;
- basis for each current standing; and
- separate completeness, condition, coverage, recurrence, and delivery axes.

Cross-diagnostic conflict/coherence requires an identified model/evaluator.
Nightshift may report unresolved conflict but cannot invent global state.
Transitions, intents, acknowledgments, suppression, route outcomes, and
annotations remain independently identified linked artifacts.

### R9.3 — inspector

The inspector consumes the same canonical contract as every reader and derives
no authority from private database layout. Evidence retrieval is separately
authorized and attributed; it neither refreshes nor reacquires.

Next checks remain proposals until accepted by an authorized Nightshift
campaign. Historical comparison preserves profile/evaluator/threshold/
subject-state/vantage differences and distinguishes raw custody,
normalization, projection, evaluation, and presentation.

### R9.4 — frontend and operations-EDA views

The Nightshift console derives from typed contracts:

- declared design: subjects, roles, profiles, schedules, providers, vantages,
  policies, and dependencies;
- realized deployment: nodes, providers, cohorts, attachments, and observed
  inventory;
- provider → NQ diagnostic → Nightshift posture topology;
- diagnosis → intent/proposal → human/AG authorization → Docket authority
  flow;
- dependency/coverage graph with projection limits, missing testimony, shared
  roots, and supported separation;
- run-slot/episode/transition/attempt/recovery/supersession/expiry lifecycle;
  and
- declared-versus-realized violations.

These are generated views, not maintained truth. Every summary drills to exact
immutable artifacts. No top-level healthy state may conceal a mandatory
non-complete category.

### R9.5 — access

Use one canonical transport-independent artifact serialization and identity.
Transport/authentication/custody wrappers have separate identities and never
replace the underlying bytes.

Require:

- CLI use of the supported read contract, not private tables;
- snapshot/generation binding on every read;
- finite cursors bound to one immutable snapshot;
- authenticated, attributed sensitive-evidence retrieval;
- access decisions and retrieval receipts that do not alter evidence;
- explicit size/time/page/retrieval bounds;
- refusal of unknown producer/schema/profile/cohort/evaluator/transport-policy
  versions; and
- logically distinct least-privilege roles even if local group membership is
  the first mechanism.

Cross-host intake preserves exact bytes/digest, producer node/build/cohort,
transport and receiving custody, authenticated sender/intended consumer,
replay/duplicate handling, and incompatible/unauthorized refusal. HTTP/TLS
alone does not establish artifact authority.

### R9.6 — evolution and consistency

An incompatible structural contract change requires a schema version. A change
to a wire field's meaning, vocabulary, or interpretation is incompatible and
also requires a new schema version; a producer cannot reuse an old field with
new meaning.

Evaluation semantics may change under a new profile, evaluator, threshold,
projection, cohort, or canonicalization identity without a schema change only
when the wire contract and every field meaning remain unchanged.

Require exact compatibility matrices, unknown-version refusal, no silent
field loss, explicit projection identity/omissions, projection-collision
vectors, canonical byte/digest tests, positive/negative/substitution/
pagination/snapshot/lossy-projection tests, and common snapshot/state
generation across all pages. Incomplete bounded export is explicit.

Old artifacts remain interpretable under original contracts. Reevaluation
under new semantics creates a new historical artifact.

Current preview coarse `HealthState`, finding/status “current” language,
`operator_work_state`, scheduler/notification component kinds, open JSON
freshness/basis, and command-shaped safe checks are quarantined. They are not
the ratified target contract.

Affected facets: both `operator_surface.typed_contracts`,
`self_diagnosis.nq`, all diagnostic rows, and Nightshift operator-loop
surfaces.

## R10 — qualification, replacement, and rollback

The objective is clean replacement, not permanent dual-stack operation.
Classic has no successor compatibility constituency for executable names,
APIs, schema/database, finding IDs, configuration layout, or quirks.

### R10.1 — isolated qualification

Before cutover, Classic remains sole portrait and notification authority.
NQ-NG qualification uses distinct config, state, runtime/deployment
generation, services/sockets/listeners, admissions/cohorts, Nightshift state,
and qualification receivers.

NQ-NG output is visibly non-authoritative and cannot page production, authorize
action, or become current consumer truth. It cannot read/import/mutate or
depend on Classic private state. A separate comparison harness may inspect
supported outputs and emit immutable comparison receipts; it owns no authority.

### R10.2 — time and event gates

Require at least 14 consecutive days per subject after freezing the exact
qualification generation, including roles/inventories, all relevant builds,
semantic and operational policies, vantages, routes, and contracts.

Qualification is time-complete and event-complete. Required events include
restart, generation change, missing/refused/stale/contradictory evidence,
expiry, custody refusal, restore, upgrade/rollback, notification failure, and
vantage loss. Daily immutable receipts preserve comparison evidence. Injected
events are identified, bounded, reversible when applicable, and distinct from
incidents.

### R10.3 — reset law

A verdict-changing change resets only rows whose declared dependency closure
includes it. Dependencies include builds, providers, admissions, profiles,
evaluators, schemas/projections/canonicalization, thresholds/baselines,
recurrence/expiry/transition/route/transport policy, role inventory,
deployment/privilege/namespace/attachments, platform behavior, and vantage
generation.

Prior evidence remains historical. A correctly represented adverse condition
or refusal is successful qualification evidence. A defect fix resets affected
rows. Documentation-only changes reset only if the executed contract was
materially wrong.

### R10.4 — functional equivalence

Compare the same subject, bounded operator question, applicable state/interval,
expected coverage, operator-visible conclusion, and required notification
behavior.

Do not preserve internal schemas, IDs, names, config, APIs, prose, severity
labels, or quirks. NQ-NG may deliberately break every Classic implementation
surface.

Each required row must satisfy its own ratified acceptance relation for
acquisition/coverage, binding, condition/contradiction/coherence/refusal,
availability/projection, current Nightshift standing, operator drill-down, and
notification custody where required. There is no universal “stronger
semantics” ordering.

Classify comparisons as row-specific equivalent behavior, satisfying behavior
with additional preserved distinctions, required Classic-only workflow
needing replacement, NQ-NG regression, or genuinely incomparable. Agreement
does not pass if both systems are wrong. Implementation details need no
replacement; retained operator workflows do. No Classic derived state migrates
as current.

### R10.5 — atomic authority switch

Switch per subject only after every required facet passes, accepted deviations
are recorded, operator workflows and views pass, current non-expired standing
exists, routes are qualified, rollback/archive are verified, and exactly one
authority is chosen.

Record subject, old/new authority generation, switch instant, last Classic and
first NQ-NG intervals, gap, portrait and notification authority, and operator
decision. There is no row-level hybrid authority. Subjects may switch
separately; estate views spanning mixed authority state it or remain
partial/refused.

After success, stop Classic, disable Classic delivery, mark it deprecated, and
fence consumers. The switch transfers diagnostic/portrait/notification
authority only; reliance, remediation, agent action, and Docket execution
remain separate.

### R10.6 — temporary emergency rollback

Preserve 14 days of per-subject rollback eligibility after switch, with
Classic not running. The sealed set includes exact binaries, config, units,
database, schemas/tooling, secret references, tested restore, and
authority/notification fencing.

Rollback is a new explicit emergency authority-switch operation. It verifies
continued applicability, fences NQ-NG, restores Classic into a new deployment
and authority generation, reacquires fresh evidence, establishes only truthful
new current standing, enables one notification authority, discloses the
NQ-NG-only interval/gap, and quarantines backlog without replay.

Starting Classic cannot revive authority or old current standing. Eligibility
ends early if unsafe. After 14 accepted days, no Classic runtime fallback,
compatibility, shadow operation, or qualification obligation remains; only the
R5 historical archive remains.

This ratification does not authorize R10 execution.

## R11 — explicit retirement dispositions

### R11.1–R11.2 — Classic runtimes

Both subjects' Classic runtimes are conditionally approved for retirement.
This approves the successor disposition and absence of compatibility
obligation, not a future mutation.

Only after subject authority switch, completion/explicit exit of rollback
eligibility, verified R5 archive, and no unresolved rollback decision may a
separately authorized retirement operation proceed.

That operation previews services/processes, packages/binaries/units,
configuration/state/sockets, credentials or secret references, expired
rollback material, retained history, and proof that no consumer remains.

### R11.3 — sushi-k user-local shape

The mutable checkout, `target/release` binaries, home-local config, and user
services are approved for replacement/retirement. Preserve enough exact
rollback/archive material to explain the old deployment. Do not carry paths,
service names, config layout, or workstation dependencies into production.
Clean-install qualification starts from empty state.

### R11.4 — `governor-code-adapter`

Retire without replacement as AG Classic deployment residue: it is down, no
retained workflow depends on it, and AG-NG defines no requirement for it.
Record an approved inventory change, not discovered absence or recovery.
Future AG-NG adapter/provider work is a new overlay decision.

### R11.5 — SMART

Reject retirement. Require conditionally applicable device-native health
testimony per declared physical device and supported access path.

Inventory physical identity; controller/HBA/enclosure/bridge/passthrough;
SATA/SAS/NVMe/USB/virtual/controller-managed class; available SMART/equivalent;
privilege/namespace/executable/provider; and translation/passthrough limits.

For an applicable device, missing privilege, tooling, identity, access, or
testimony remains missing/refused. Invocation success is not health; stale or
incomplete attributes cannot clear a condition. A per-device or bounded-class
unsupported exclusion is explicit and visible. Virtual volumes, loop devices,
mapper targets, and filesystems do not all require SMART.

### R11.6 — local Classic Monitor probe

Retire the localhost HTTP facade probe. It proves only that a local facade
responded; it does not prove NQ, Nightshift, host, or external health.

This is retirement, not semantic equivalence. Preserve required distinct
self-diagnostics for NQ runtime/liveness, custody/persistence,
provider/admission/execution, local read API/socket, catalog/schema,
store-pressure/refusal, Nightshift schedule/posture/intake, and frontend
access/rendering. A producer cannot establish total availability merely by
self-reporting. External DNS/TLS/application reachability uses R7 vantages.

### Retirement execution law

For every retirement:

- the disposition removes the successor obligation only under its stated
  conditions;
- history remains valid;
- the inventory change is explicit and versioned;
- retirement-created absence is not recovery; and
- service control, removal, purge, deletion, credential revocation, or other
  mutation requires separate human/AG authorization and governed execution.

Affected facets: `legacy.classic_runtime` on both subjects,
`legacy.user_local_deployment_shape`,
`application.governor_code_adapter`, `storage.smart`, and sushi-k's
`telemetry.prometheus_blackbox` local-probe row.

## Cross-cutting nonclaim audit

Nothing in R1–R11 permits:

- unknown, stale, refused, missing, unsupported, partial, contradictory, or
  unconfigured evidence to become healthy;
- a last clean diagnostic to remain current after expiry;
- loop or service liveness to become host/application health;
- provider or producer assertions to grant standing or reliance;
- package/process/provider multiplicity to become corroboration;
- a shared evidence root to be counted twice;
- an agent, Nightshift, frontend, notification receipt, or ordinary endpoint
  to create NQ semantics or action authority;
- Nightshift cross-diagnostic posture to become an NQ recursive disposition;
- an unstructured state bag to imply co-occurrence;
- Classic state to become NQ-NG current truth;
- arbitrary PromQL or runtime profile plugins; or
- retirement disposition, diagnostic depth, or alert delivery to authorize
  mutation.

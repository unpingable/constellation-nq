# NQ successor sequencing

Status: living implementation sequence under the ratified
[`NORTH_STAR.md`](NORTH_STAR.md), 2026-07-27.

This sequence turns the north-star into cumulative operational campaigns. A
campaign may use a bounded vertical for implementation and testing, but no
individual profile, provider, or detector earns a role-complete product claim.

## Governing rules

1. NQ-NG is the successor development line; Classic remains operational
   authority until an explicit switch.
2. Preserve the current NQ-NG custody, compiled-profile, refusal, and atomic
   publication boundaries.
3. Recover deployed requirements before choosing parity work.
4. Implement functional equivalence NQ-NG-native. Do not merge Classic,
   migrate its database, or reproduce its pack/runtime/dashboard architecture.
5. Every required portrait domain must render an explicit coverage and
   condition outcome. Silence is not success.
6. Work on clean local `main` lines in coherent commits. Do not hide unrelated
   concurrent work in campaign commits.
7. The current execution constraint is local commits only. Do not push, tag,
   publish, release, deploy, or change remote state until the operator lifts
   that constraint explicitly.

## Implementation posture — greenfield parity, VM first

Do not begin replacement work by wholesale-porting or backporting Classic into
NQ-NG. Continue building the greenfield successor cumulatively until it meets
the exact operator questions and acceptance relations in the ratified Portrait
v1 manifest.

Classic has two roles in that work:

- **capability donor:** recover bounded algorithms, fixtures, edge cases, and
  still-required operator workflows; and
- **qualification comparator:** later compare the same subject, bounded
  question, state/interval, coverage, conclusion, and notification behavior.

Classic is not the source architecture. Its collectors, pack framework,
database, APIs, dashboard, executable names, configuration layout, and quirks
are not implementation parity targets.

Prefer a small disposable VM over `sushi-k` as the initial implementation and
qualification substrate. The VM should exercise installed artifacts from
empty state, explicit role and synthetic subject identity, clean state
directories, witness/provider admission, hostile evidence cases, package
lifecycle, upgrade/rollback, backup/restore, and repeatability without a
developer checkout inside the guest.

VM results may earn generic platform, installation, profile, witness, and
operator-journey evidence. They cannot earn `sushi-k` or `labelwatch-host`
Portrait completeness, because those verdicts require the subjects' closed
inventories, application contracts, real vantages, and later isolated
qualification.

Only after NQ-NG meets the relevant ratified manifest rows does it meet Classic
at the live comparison gate. Work on the real subjects should then be
configuration and isolated qualification of a developed product, not
unfinished product development.

This posture records campaign direction only. It does not broaden the bounded
blocker-closure authority below, authorize general Stage 2 implementation, or
permit deployment, parallel qualification, authority switch, or cutover.

## Stage 0 — direction ratification

Record the selected-successor status, the operational north-star, and this
sequence on NQ-NG `main`. Preserve prior status records, audits, receipts, and
the `v0.1.0` tag as historical evidence. This stage changes no executable
semantics.

Completion means the repository has one current direction and no current
pointer presents the superseded 2026-07-26 mechanism-only decision as policy.

## Stage 1 — truth and qualification baseline

Two independent lanes may proceed in parallel.

### Lane A: restore a green development baseline

- Reproduce and repair the known NQ-NG test failures without broadening
  product semantics.
- Record environment-specific limits separately from product failures.
- Run the repository-native formatting, strict Clippy, protocol/profile,
  system-contract, packaging, reproducibility, hardening, release-build, and
  clean offline-source gates.
- Do not claim the successor baseline is green from the earlier partial audit.

### Lane B: deployed-capability declaration

Inventory the actual logical `sushi-k` and logical `labelwatch-host`
(currently Linode-hosted) installations:

- exact Classic binary/schema/config identities;
- enabled collectors and concrete targets;
- required services, containers, processes, filesystems, storage, devices,
  interfaces, routes, listeners, endpoints, logs, databases, and metrics;
- thresholds, baseline ownership, maintenance behavior, and retention;
- notification transports, recipients, retry expectations, and escalation;
- Labelwatch and Driftwatch operator questions and application-owned state;
- required Docket, Continuity, Nightshift, or reliance consumers; and
- acceptable parallel-run, cutover, and rollback windows.

The deliverable is a versioned capability manifest with each row classified
as currently present, required for cutover, or permitted to retire. Checked-in
example configuration is not deployment proof.

### Stage-1 gate

Ratify **Host Operational Portrait v1** from the deployed manifest. The
ratification fixes required portrait sections, subjects, vantages, expected
coverage, operator tasks, notification obligations, and the exact meaning of
functional equivalence. Later implementation may add coverage but may not
silently delete a required row.

**Current gate decision (2026-07-27):** the
[Portrait v1 specification](../audit/host-operational-portrait-v1-ratification/HOST_OPERATIONAL_PORTRAIT_V1.md)
and [44-row manifest](../audit/host-operational-portrait-v1-ratification/RATIFIED_CAPABILITY_MANIFEST.json)
are operator-ratified. `sushi-k` and `labelwatch-host` completeness are both
not earned. Classic replacement, parallel qualification, and cutover remain
unauthorized.

The only authorized follow-on is the bounded
`HOST-OPERATIONAL-PORTRAIT-V1-BLOCKER-CLOSURE` unit. It may perform records,
design, evidence gathering, and narrowly necessary implementation to close:

1. exact versioned per-subject inventories and exclusions;
2. Labelwatch/Driftwatch native observation and profile-semantic contracts;
3. the non-colliding production namespace;
4. sushi-k's exact platform binding; and
5. required external-vantage identities and qualification inputs.

It may not deploy, mutate services, begin parallel qualification, switch
authority, execute retirement, publish, tag, release, or claim subject
completeness. When those blockers close, a focused conformance review updates
each subject verdict against the already-ratified specification. It repeats
the full policy ratification only if the contract materially changes.

## Stage 2 — witness, packaging, and cohort seam

General Stage 2 implementation is not authorized by the current decision.
Only work strictly necessary for the bounded blocker-closure unit above may
touch Stage 2 implementation seams.

- Reconcile useful `nq.witness.v0` concepts into the existing NQ helper and
  `EvidenceReport` path; do not promote producer-declared standing.
- Establish one authoring/conformance kit and Debian packaging convention for
  independently installed witnesses.
- Keep canonical protocol and NQ semantics in NQ-NG; keep reusable acquisition
  implementations in `nq-witness` or their domain repository.
- Define role bundles so a host installation composes core plus its complete
  default host witness set, while fabric nodes need not install it.
- Implement static profile-cohort assembly and a sealed cohort manifest.
- Prove cohort install, admission, mismatch refusal, upgrade, rollback,
  retirement, and private-configuration nonleakage.

The stage stops rather than adding a runtime plugin system. A private profile
that cannot be represented honestly receives a private static cohort or waits
for an upstream profile; it is not forced into a misleading generic schema.

## Stage 3 — default host acquisition foundation

Deliver the default host acquisition and self-diagnosis foundation
cumulatively:

- identity, boot epoch, kernel, uptime, and time basis;
- CPU/load/pressure and memory/swap/pressure;
- complete in-scope filesystem and mount inventory with bytes, inodes, and
  read-only state;
- required systemd lifecycle, declared process-presence coverage, and recent
  transitions;
- interfaces, routes, basic listener inventory, and bounded local network
  state; and
- NQ provider, helper, store, bounded diagnostic-runner, and expected-coverage
  self-diagnosis.

Each bounded family must have an explicit compiled-profile path, bounded
helper/provider path, hostile fixtures, live bounded specimen, and generic
diagnostic read projection. The current `nq.host/v1` identity is not silently
expanded; new semantics require an explicit new profile or version under the
registry rules. One request invokes one exact profile; do not recreate
Classic's all-collectors envelope.

Stage 3 earns only the default acquisition foundation. It cannot earn Host
Operational Portrait v1. That verdict additionally requires every Stage-1
required overlay and application cohort plus the Stage-6 NQ inspection,
Nightshift recurrence and enterprise-console, notification, and clean-operator
loop. The Stage-3 gate requires every default row to have an explicit outcome
and the clean host-role package to install from documented artifacts without
repository-relative knowledge.

## Stage 4 — required common overlays and external vantages

Implement only overlays required by the Stage-1 manifest, selected from:

- Docker/container-specific state and enriched process/listener exposure;
- SQLite/WAL and bounded journal/kernel-event evidence;
- ZFS, SMART, GPU, Kea, and other substrate-specific profiles;
- DNS, TLS, HTTP, ICMP, and external blackbox vantages; and
- Prometheus exposition or query intake.

Use Classic, `nq-witness`, `nq-security-witness`, `nq-blackbox`, and
`nq-hatchet` as bounded algorithm/fixture donors. Use `zab2nq` only to find
missing diagnostic families and adversarial cases.

The first Prometheus provider must prove exact raw-response replay, structural
dimension survival, separately established coverage, timestamp separation,
warning and partial-result retention, recording-rule/federation lineage
refusal, and missing-series nonclaim. It may not accept arbitrary PromQL as NQ
fact.

## Stage 5 — application cohorts and recursive testimony

- Build Labelwatch acquisition and its private witness package in the
  Labelwatch repository.
- Build Driftwatch acquisition and its private witness package in the
  Driftwatch repository.
- Compile truly domain-specific profiles into an explicitly identified private
  cohort; promote only semantics that have proved generally reusable.
- Implement the standard child-testimony boundary needed for the private domain
  node to report outward.
- Preserve claim surface, evidence availability, per-claim evidence
  dependencies and state bindings, projection limits, contradictions,
  coverage gaps, and consumer-owned reliance at the receiving NQ boundary.
- Admit child testimony only as evidence for the same exact diagnostic
  question named by the receiving profile; shared subject or similar wording
  is not sufficient.
- Prove adversarially that a receiving diagnostic cannot reconstruct
  distinctions erased by child testimony or count a child as independently
  corroborating without a consumer-evaluated, claim-relative supported
  separation assessment.
- Prove that host, generic service, application-internal, bridge, and remote
  perspectives remain distinct and that shared failure domains do not create
  false corroboration.

Application repositories own phase maps and native facts. They do not import
NQ's evaluator, database, or authority surfaces. NQ owns what conclusions
follow from their admitted testimony within one exact diagnostic profile. The
NQ-to-NQ boundary preserves and qualifies testimony; it does not own
cross-diagnostic operational synthesis.

## Stage 6 — diagnostic-to-operational-posture loop

Current bounded progress: the frozen `nq.diagnostic_execution.v1` package and
its sibling `nq.diagnostic_execution.v2` package contain canonical and hostile
vectors. One fresh admitted `nq.host/v1` load-pressure execution commits exact
v2 bytes atomically with its source history for a determinate result, governed
input/detector refusal, or typed no-byte acquisition failure; an admission
refusal creates no execution artifact. Schema-v5 custody supports restart-safe
inspection and exact export/import, and the read-only Nightshift consumer
evaluates closed inventory/currentness and explicit cross-vantage concordance.
This remains a local untagged vertical. Nightshift intake and recurrence are
not installed or durable, the production namespace/identity catalog is not
implemented, only one diagnostic family emits the contract, and no real
subject or independent external vantage is involved.

- Stabilize NQ's machine-facing read and export contract for individual
  diagnostic executions: exact profile, subject, scope, vantage, complete
  expected/received/admitted/refused/failed/excluded/selected input accounting,
  per-claim evidence and state bindings, coverage, admissibility, disposition
  or refusal, and limitations.
- Retain `nq-monitor`, if that product name remains, as a semantics-free
  execution inspector or disposition explorer. It is not the estate
  operations dashboard.
- Build Nightshift's operational model for declared diagnostic profiles,
  subjects and vantages, recurrence and campaign state, last known result with
  evaluation time and current applicability, unresolved gaps, and proposed
  next diagnostic.
- Prove Nightshift recurrence is governed diagnostic orchestration rather than
  an unrecorded cron loop: declared purpose, expected check-ins, jitter,
  backoff, escalation, campaign completion, and prior-result dependencies
  remain inspectable.
- Prove cross-diagnostic composition in Nightshift without laundering the NQ
  boundary: multiple profiles, times, and vantages remain distinguishable;
  agent derivations are cited and replayable; human assertions are attributed
  and durably recorded; and the result is a read-only operational posture
  rather than a stronger NQ disposition.
- Qualify Maude or another frontend over those typed contracts. The primary
  operations view is a Nightshift enterprise console showing diagnostic
  profiles and their last-known and current-reliance states under an identified
  Nightshift consumer policy.
- Keep acquired evidence, scoped diagnostic result, and operational posture
  visibly separate in every presentation.
- Add durable notification delivery with visible
  queued/attempted/delivered/failed state. Notification intent, audience,
  suppression, and escalation are owned by Nightshift or explicit operator
  policy; a delivery facet records transport attempts and cannot infer page
  authority from a raw NQ finding.
- Prove provider acquisition cadence, Nightshift diagnostic recurrence,
  missing check-ins, provider failure, storage failure, campaign failure, and
  notification failure remain operationally distinguishable and
  self-diagnosing.
- Expire a previously usable diagnostic result solely through the declared
  recurrence and time basis. Nightshift's current posture must change to the
  exact overdue, narrowed, or unknown result required by its contract while
  the original NQ disposition or refusal remains byte-identical with the same
  identity.
- Qualify task-oriented operator questions: what is established, what is
  unknown, why a prior result is or is not currently usable, which fault
  boundary is supported, and which bounded next diagnostic would reduce the
  decision-relevant uncertainty.
- Run task-based clean-room qualification using only installed documentation
  and public command help.

A critical supported condition must not coexist with a no-action headline.
Unknown, stale, missing, refused, and unsupported evidence must not render as
healthy or as subject failure. A last-known result must not render as current
without separately established freshness, state applicability, and coverage.
Nothing in this stage grants actuation authority.

## Stage 7 — estate qualification and replacement

1. Install isolated NQ-NG candidates for logical `sushi-k` and logical
   `labelwatch-host` with
   distinct configuration, database, admission, socket, service, console, and
   archive identities.
2. Observe the same declared targets while Classic remains alert and
   operational authority.
3. Compare underlying facts, intervals, coverage, refusals, operator
   conclusions, and notification delivery—not database rows, finding IDs, or
   severity names.
4. Exercise upgrades, rollback, restarts, checkpoints, missing providers,
   malformed inputs, and notification failure.
5. Freeze Classic with exact binaries, configuration, logs, SQLite/WAL backup,
   and a content-digest archive manifest.
6. Initialize fresh NQ-NG stores, collect current evidence, and obtain explicit
   signoff on the exact candidate and configuration.
7. Switch authority and record the historical boundary. Do not import Classic
   findings as current NQ-NG state.
8. Preserve a rehearsed rollback. Treat the split observation interval as an
   explicit limitation rather than trying to merge histories.

Public-repository transition follows functional equivalence and stable
operation. It is not how equivalence is created.

## Stage 8 — governed operation handoff

- Define one exact, non-authoritative Nightshift operational-proposal carrier
  that binds every informing NQ disposition/refusal and Nightshift composition
  artifact without reconstructing either from a rendered endpoint.
- Pass that proposal through explicit human or AG authorization and into
  Docket's existing governed execution boundary.
- Preserve proposal, authorization, refusal, dispatch, execution, observation,
  and reconciliation identities as different objects.
- Prove that a raw NQ result, a Nightshift posture, an agent interpretation, or
  a notification receipt cannot independently authorize execution.
- Qualify refusal and no-op paths before any separately authorized bounded live
  specimen.

This stage is not required to pretend that diagnosis itself grants actuation.
It sequences the exact handoff by which separately authorized operations may
consume diagnostic decision support. No Stage-1 record authorizes Docket
changes or a live mutation.

## Cross-stage acceptance corpus

Every stage extends one cumulative corpus covering:

- exact provider, helper, profile, detector suite, evaluator artifact, cohort,
  subject, scope, vantage, state, and evidence binding;
- positive, explicitly absent, partial, stale, missing, refused, malformed,
  contradictory, and unsupported cases;
- recursive projection collisions in which erased child distinctions remain
  unavailable until exact stronger evidence is retrieved;
- agent replays in which deterministic diagnostic inputs remain byte-identical,
  every interpretation cites its inputs and derivation identity, and model
  output cannot overwrite evidence, disposition, refusal, or authority;
- restart, checkpoint, replay, upgrade, rollback, and retirement;
- clean package installation from empty mutable state;
- no private targets, paths, credentials, or thresholds in public defaults;
- NQ diagnostic inspection, Nightshift enterprise-console, and notification
  behavior; and
- correspondence against Classic on required deployed facts.

No verdict is earned solely from source inspection when execution is possible.

## Immediate gate

Stage 1 and the operator ratification gate are complete. Host Operational
Portrait v1 is the normative specification; neither subject has earned
completeness. The five focused blocker-closure obligations remain open.

The operator separately authorized and completed the bounded
[`NQ–Nightshift Stage 6 foundation`](../audit/nq-nightshift-stage6-foundation/CAMPAIGN.md)
and a later published-consumer/cross-vantage-concordance vertical. The latter
earned the narrow exact-byte producer/consumer path described above, not
durable or deployed live-engine correspondence.

The subsequent records-only product-completeness campaign ratified separate
chassis, generic-host, subject, Classic-replacement, NQ-owned-constellation,
and cross-system finish lines plus an evidence-derived remaining campaign
graph. It did not authorize any of those implementation nodes. Current
authority comes only from a later explicit operator decision; nothing here
authorizes deployment, parallel qualification, notification, authority
switch, or cutover.

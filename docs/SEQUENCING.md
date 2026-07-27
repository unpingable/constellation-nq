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

Inventory the actual `sushi-k` and Linode installations:

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

## Stage 2 — witness, packaging, and cohort seam

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
- NQ provider, helper, store, scheduler, and expected-coverage self-diagnosis.

Each bounded family must have an explicit compiled-profile path, bounded
helper/provider path, hostile fixtures, live bounded specimen, and generic
read projection. The current `nq.host/v1` identity is not silently expanded;
new semantics require an explicit new profile or version under the registry
rules. One request invokes one exact profile; do not recreate Classic's
all-collectors envelope.

Stage 3 earns only the default acquisition foundation. It cannot earn Host
Operational Portrait v1. That verdict additionally requires every Stage-1
required overlay and application cohort plus the Stage-6 Monitor, scheduling,
notification, and clean-operator loop. The Stage-3 gate requires every default
row to have an explicit outcome and the clean host-role package to install
from documented artifacts without repository-relative knowledge.

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
dimension survival, independent coverage, timestamp separation, warning and
partial-result retention, recording-rule/federation lineage refusal, and
missing-series nonclaim. It may not accept arbitrary PromQL as NQ fact.

## Stage 5 — application cohorts and recursive composition

- Build Labelwatch acquisition and its private witness package in the
  Labelwatch repository.
- Build Driftwatch acquisition and its private witness package in the
  Driftwatch repository.
- Compile truly domain-specific profiles into an explicitly identified private
  cohort; promote only semantics that have proved generally reusable.
- Implement the standard child-disposition boundary needed for the private
  domain node to report outward.
- Preserve claim surface, evidence availability, state frontier, projection
  limits, contradictions, coverage gaps, and consumer-owned reliance at the
  parent.
- Prove adversarially that a parent cannot reconstruct distinctions erased by
  a child summary or count a child as independent corroboration without a
  claim-relative independence warrant.
- Prove that host, generic service, application-internal, bridge, and remote
  perspectives remain distinct and that shared failure domains do not create
  false corroboration.

Application repositories own phase maps and native facts. They do not import
NQ's evaluator, database, or authority surfaces. NQ owns what conclusions
follow from their admitted testimony.

## Stage 6 — full operator loop

- Stabilize a generic read model for the complete host/application portrait.
- Build `nq-monitor` as a semantics-free client showing subject, vantage,
  evidence frontier, state frontier, conditions, contradictions, coverage,
  limitations, and safe next checks.
- Add durable notification delivery with visible queued/attempted/delivered/
  failed state and new/escalated/resolved suppression.
- Prove local scheduling, missing check-ins, provider failure, storage failure,
  and notification failure are self-diagnosing.
- Run task-based clean-room qualification using only installed documentation
  and public command help.

A critical supported condition must not coexist with a no-action headline.
Unknown, stale, missing, refused, and unsupported evidence must not render as
healthy or as subject failure.

## Stage 7 — estate qualification and replacement

1. Install isolated NQ-NG candidates for `sushi-k` and the Linode with
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

## Cross-stage acceptance corpus

Every stage extends one cumulative corpus covering:

- exact provider, helper, profile, detector suite, evaluator artifact, cohort,
  subject, scope, vantage, state, and evidence binding;
- positive, explicitly absent, partial, stale, missing, refused, malformed,
  contradictory, and unsupported cases;
- recursive projection collisions in which erased child distinctions remain
  unavailable until exact stronger evidence is retrieved;
- restart, checkpoint, replay, upgrade, rollback, and retirement;
- clean package installation from empty mutable state;
- no private targets, paths, credentials, or thresholds in public defaults;
- Monitor and notification behavior; and
- correspondence against Classic on required deployed facts.

No verdict is earned solely from source inspection when execution is possible.

## Immediate next campaign

After this record-only stage, the next authorized implementation work is
Stage 1: restore the NQ-NG qualification baseline and produce the deployed
capability manifest. Provider expansion, Prometheus integration, witness
porting, application cohorts, and Monitor implementation wait for those gates.

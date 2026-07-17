# NQ-ng: Professional, Local-First NQ Successor

## Summary

The audit confirms that NQ’s extensibility problem is structural: adding GPU currently fans through roughly 25 files, fixed collector enums and batches, profile-specific SQL, repeated `collector_runs` constraint rebuilds, and duplicated execution/persistence logic. The in-progress GPU migration also breaks the existing upgrade test. The successor should therefore be greenfield, not an incremental refactor.

NQ-ng will use this governing rule:

> Mechanically open integrations, compiled and versioned semantics.

The first release consists of:

- `nqd`: one resident service owning scheduling, helper supervision, admission, evaluation, storage, notifications, API, and console.
- `nq`: the complete operator CLI.
- Out-of-process witness helpers using a stable, language-neutral protocol over stdio or supervised Unix sockets.
- SQLite storing durable cross-profile evidence facts and bounded profile payloads—not the current catalog of hardware and integrations.
- A hard successor cut: preserve every legacy byte, inherit no legacy verdict.

Claim verification, governed inquiry, remote fleet transport, WLP integration, and action authorization remain separate later packages or slices.

## Public Ontology and Interfaces

### Stable vocabulary

| Concept | NQ-ng meaning |
|---|---|
| Family | Unversioned organizational domain such as SMART or DNS; carries no runtime authority. |
| Profile | Compiled, versioned semantic contract defining observation kinds, coverage vocabulary, subject identity, bounds, basis, vantage, freshness, disturbance assumptions, and validation laws. |
| Implementation | Helper code lineage/build capable of implementing a profile. |
| Instance | NQ-owned deployment binding of implementation, profile, execution context, scope, and capability ceiling. |
| Run | One bounded collection attempt, including spawn, timeout, disconnect, and protocol failures. |
| Report | Immutable helper output from a successful protocol exchange; its own `complete`, `partial`, or `failed` status is separate from run success. |
| Observation | Profile-validated record with kind, subject, ordinal, observation time, and bounded typed payload. |
| Detector | Compiled, versioned rule over admitted observations/history. |
| Finding | Durable bounded operational diagnosis with evidence references; never a proof, command, or authorization. |
| Refusal | Typed explanation from the exact boundary and instance that could not proceed. |
| Claim | A later-package bounded proposition evaluated through compiled rules; never helper-owned. |
| Authority | Outside NQ. Helpers, reports, findings, hashes, and receipts do not authorize effects. |

Maintain a private crosswalk from each runtime invariant to its enforcement point, hostile test, and applicable Lean result. Public documentation uses ordinary product terminology rather than exposing Lean module topology.

Key inherited invariants are:

- Shape conformance does not synthesize admissibility.
- A binary digest identifies bytes; it does not qualify the implementation.
- Staleness is loss of reliance, not negation.
- Renewal creates a new report/basis; old evidence is never refreshed in place.
- Missing testimony cannot resolve a condition or create a green result.
- Scope, vantage, and capability may narrow but never expand at runtime.
- Refusals retain the exact responsible instance and boundary.
- Multi-witness findings use explicit detector composition, never consensus-by-counting.

### Helper protocol

Publish these authoritative contracts:

- `nq.helper.request.v1`
- `nq.helper.response.v1`
- `nq.evidence_report.v1`
- Canonical JSON Schemas, fixtures, compatibility rules, and conformance corpus.

Use newline-delimited UTF-8 JSON with exactly one bounded response per request. Both carriers implement the same request/response exchange:

- `stdio`: one-shot process; request on stdin, response on stdout, logs on bounded stderr.
- `unix`: long-lived helper supervised and launched by `nqd`; private socket path, strict permissions, `SO_PEERCRED` verification against the expected child, request/response only.
- No asynchronous event streaming in v1.

Each request carries:

- Request ID and exact protocol version.
- NQ-owned instance ID.
- Exact profile ID, version, and digest.
- Subject/scope/vantage binding.
- Granted capability subset.
- Monotonic deadline and response/observation bounds.
- Optional NQ-owned checkpoint for bounded log/event polling.

Each response echoes the request and returns either a report or typed refusal. Reports contain observation time, report status, complete controlled coverage declarations, bounded observations, structured errors, backend provenance, and an optional next checkpoint.

Helpers may describe supported profiles and capabilities, but that declaration is untrusted. They may not emit claims, admission decisions, detector rules, `authoritative_for`, remediation hints, or severity.

Keep these result planes distinct and persist each independently:

```text
acquisition → protocol validation → admission → report status → detector evaluation
```

A valid `failed` report is retained as testimony. A transport failure creates only a run record. EOF, exit, disconnect, timeout, malformed framing, profile refusal, capability escape, and inner report failure are different outcomes.

### Profiles, SDK, and registration

Create a small public Rust SDK containing protocol DTOs, builders, canonicalization, and client-side checks. The protocol and conformance CLI remain authoritative.

Also ship one tiny Python reference helper implementing a conformance-only profile to prove that the contract is not a Rust serialization ABI. It is not a supported Python SDK.

Compiled profile modules implement a narrow `ProfileModule` interface and register once in an explicit compile-time registry. A module owns:

- Canonical descriptor and profile digest.
- Strict report and observation validation.
- Observation and coverage vocabularies.
- Required-field and consistency rules.
- Subject identity and correlation rules.
- Scope, vantage, access-path, freshness, basis, regime, and cardinality limits.
- Typed refusal production.
- Typed projection and separately versioned detectors.

No runtime Rust libraries, directory scanning, linker inventory magic, YAML predicates, arbitrary SQL rules, or dynamic semantic plugins.

Extension promises:

- New instance: config and admission only.
- New implementation of an existing profile: helper deployment and re-admission only.
- New profile: one compiled module, fixtures, and one registry entry; normally no storage migration.
- New detector or claim mapping: compiled Rust and tests.
- New shared evidence/lifecycle law or deliberately stable SQL projection: may justify a migration.

### Configuration and admission

Use human-edited TOML for intent and machine-produced canonical JSON for admission records.

Configuration names the instance, command, carrier, requested profile, schedule/jitter, scope/vantage, capability ceiling, execution identity, checkpoint policy, and resource limits.

`nq witness admit`:

1. Resolves the executable without following unsafe path replacements.
2. Hashes the opened executable bytes and records the complete relevant execution chain: script, interpreter/wrapper, fixed argv, and available backend/tool identities.
3. Resolves the compiled profile and digest independently.
4. Runs protocol/conformance checks and a bounded dry collection.
5. Intersects declared capabilities with the configured ceiling.
6. Writes a candidate `nq.admission_lock.v1` containing config digest, executable/profile/protocol identities, conformance result and tool version, admission time, and local operator identity.
7. Atomically activates the config and lock only after full validation.

`nqd` recomputes all locally verifiable facts and refuses drift. It never refreshes the lock automatically. Config drift, binary drift, profile drift, and malformed admission are separate diagnostics.

On admission changes, stop scheduling immediately, allow an already-bound request to finish only within its existing deadline, record it under the binding active at start, then terminate persistent helpers. Explicit revocation terminates immediately.

## Runtime, Storage, and Operator Product

### Collection and evaluation engine

Schedule every instance independently with cadence, jitter, deadline, retry/backoff, and resource bounds. Collection never occurs because an API route was read.

The subprocess runner must:

- Execute fixed argv without a shell.
- Drain stdout and stderr concurrently.
- Enforce frame, byte, observation, time, and process-group limits.
- Terminate and reap on timeout.
- Sanitize environment and working directory.
- Record execution identity and resource outcomes.

Commit admitted reports independently. Detector evaluation uses a consistent database watermark and explicit temporal-alignment/freshness rules rather than pretending independently scheduled witnesses formed one simultaneous generation.

Run relevant detectors after new evidence and run periodic freshness sweeps. Detectors return one of:

- Condition present.
- Condition explicitly absent under sufficient current coverage.
- Cannot evaluate, with refusal.

Only the second may resolve a finding. Loss of acquisition, stale evidence, partial coverage, or profile refusal changes observability and may create an instance-level finding; it never clears child conditions.

### Generic append-only SQLite substrate

Use relational columns for cross-profile facts and bounded canonical JSON for profile payloads:

- Profile descriptor snapshots.
- Admission history and binding digests.
- Witness runs and acquisition outcomes.
- Exact bounded raw submissions and raw-byte digest.
- Admitted canonical reports and semantic digest.
- Observations keyed by report, ordinal, kind, and profile-validated subject.
- Report/observation coverage states.
- Ordered report errors and refusals.
- Evaluation runs and evidence watermarks.
- Append-only finding events and evidence references.
- Current finding/status projections.
- Notification outbox and delivery attempts.
- Retention tombstones and legacy-cut references.

Store raw-byte identity and canonical semantic identity separately. Unknown profiles, unknown kinds, malformed documents, duplicate coverage, scope escape, and capability escape remain queryable rejected custody artifacts but never reach detectors.

Do not flatten observation fields into EAV rows or arbitrary labels. Profile JSON is acceptable because it is versioned, strictly validated, bounded, fixture-backed, and stored with its descriptor. Optional optimized projections must be rebuildable from admitted reports and are added only after a demonstrated query/performance need.

Support multiple instances of the same profile on one source. Identity is instance/report/subject based, never merely host based.

Prometheus remains a separate raw-sample lane with bounded labels, target provenance in series identity, and cardinality quotas. Raw samples cannot feed profile detectors unless an admitted helper converts them into a profile report.

### Findings and public consumer boundary

Define `nq.finding_snapshot.v2` with:

- Opaque NQ-owned `finding_id`; consumers never reconstruct it.
- Typed instance, detector, profile, and subject identity.
- Detector version/digest and evaluation revision.
- Condition, evidence/visibility, and operator-work states kept separate.
- Severity, summary, evidence, limitations, and safe next checks.
- Evidence report digests and observed/received/evaluated times.
- Freshness/basis/refusal details.
- Origin mode and optional historical references.

Define `nq.status_snapshot.v1` for daemon, database, profile catalog, admission, scheduler, instance, evaluation, and notification health.

Expose identical DTOs through:

- Versioned local API over `/run/nq/nqd.sock`.
- `nq findings export`, `nq status export`, and complete CLI workflows.
- A loopback-only server-rendered console with minimal JavaScript and no frontend build system.
- Read-only bounded SQL over documented public views; saved SQL never becomes detector semantics.

The console is initially read-heavy. Destructive maintenance stays CLI-only. Use ordinary operations language—“collection failed,” “report refused,” “evidence stale,” “condition active,” “resolved”—with precise codes/details available beneath it. Do not make Lean terminology, internal Δ codes, or SRE marketing language the primary interface.

Update Nightshift in the coordinated cutover to consume finding/status v2 through `nq` or the local API. Remove its NQ DB path, liveness-file path, canonical-key reconstruction, locally invented evidence hash, and silent enum fallbacks. Nightshift remains strictly read-only. Its contract tests must exercise the shipped `nq` binary and may not skip when integration is absent.

### Install, operate, and upgrade

Ship checksummed Linux AMD64/ARM64 tarballs and Debian packages containing `nq`, `nqd`, systemd units, profile descriptors, schemas, fixtures, console assets, and first-party helpers. Packages create the service user/group and standard directories but never initialize, migrate, overwrite configuration, or purge data implicitly.

Default layout:

- `/etc/nq/nq.toml`
- `/var/lib/nq/nq.db`
- `/var/lib/nq/admissions/`
- `/var/lib/nq/backups/`
- `/run/nq/nqd.sock`
- `/run/nq/helpers/`

Provide complete commands for `init`, `config check/diff/apply`, `witness test/admit/rotate/rollback`, `doctor`, `backup`, `restore`, `admin upgrade`, status/query/export, and clean uninstall versus explicit purge.

Core schema upgrades are explicit maintenance:

1. `nqd` refuses old or newer incompatible schemas and names the required command.
2. `nq admin upgrade` requires exclusive ownership, validates integrity, disk space, migration chain, and binary compatibility.
3. It creates and verifies a digest-addressed backup.
4. It migrates transactionally or through an explicit staged protocol.
5. It verifies integrity, schema invariants, record counts, and public read models.
6. It writes an upgrade receipt containing versions, migrations, binary identity, backup identity/location, times, result, and operator identity.
7. Failure leaves the old DB untouched or marks the staged copy explicitly quarantined.
8. Rollback restores a verified backup; no automatic downgrade or reverse-migration assumption.

Use a durable notification outbox with visible pending/delivered/failed states, bounded retries, and idempotency keys. Profile modules never deliver notifications themselves.

## Delivery, Cutover, and Future Networking

### Staged operational parity

1. **Spine proof / developer preview**
   - Host, services, SQLite/WAL, and exposure profiles.
   - Protocol, both carriers, Rust SDK, Python specimen, registry, admission, generic store, detector lifecycle, CLI/API/console, backup/upgrade skeleton.

2. **Hardware and storage beta**
   - ZFS, SMART, and GPU profiles/helpers.
   - Port existing operational detectors with newly earned nq-ng semantics.
   - Exercise privilege boundaries, unsupported platforms, heterogeneous payloads, same-profile multiple instances, and helper replacement.

3. **Messy inputs and sample lane**
   - Log-activity profile using bounded request/response checkpoints; NQ advances checkpoints only after admitted report commit. Rotation, gaps, truncation, and replay are explicit.
   - Prometheus raw-sample lane with target-aware identity and quotas.
   - Complete notifications, retention, public SQL, install/restore/upgrade drills.

4. **Replacement-ready cut**
   - Every current operational detector/profile is ported; retirement requires an explicit operator-approved record and replacement story.
   - Parity means required coverage and operator capability, not schema, finding identity, or inherited verdict equivalence.
   - Run old NQ and nq-ng side by side without shared state or dual writes, compare operational outcomes, then perform one hard cut.

At cutover:

- Stop old NQ and take final exports.
- Produce an immutable legacy cut manifest with DB digest/size, schema, final code and binary identities, cut time, export inventory, and record counts.
- Preserve a frozen read/export binary.
- Initialize nq-ng with a genesis record referencing the manifest digest.
- Permit new findings to cite `legacy-nq://…` historical references, but never import legacy findings as active/current/equivalent.
- Update Nightshift and other live consumers, then retire old services.

### Network observation profiles

After local parity, add ordinary profiles in increasing operational invasiveness:

1. DNS query/response from a named resolver and vantage.
2. TLS presentation/validation with endpoint, SNI, trust-basis version, clock basis, and horizon.
3. ICMP/TCP/HTTP reachability with named vantage and control probe.
4. Path/route observations with explicit method, gaps, and uncertainty.
5. Derived connectivity-filtration and cut/bottleneck findings under declared thresholds.

A single vantage never establishes global reachability or “network health.” Percolation/spectral work follows only after the ordinary evidence model and a concrete forcing case justify it.

### Future WLP custody transport

Reserve a transport-neutral `ObservationInput` normalization boundary now, but add no WLP dependency, port, enrollment, or fleet configuration in v1.

The live WLP library does not yet provide transport, durable append, append ACKs, identity verification, or retry/idempotency. Future integration is gated on WLP ratifying:

- Strict wire/version validation.
- A domain-opaque testimony/cargo artifact—not reuse of `AuthorizationReceipt`.
- Claimed-hash/signature and peer/key-standing responsibilities.
- Durable append with an application-level ACK.
- Idempotent at-least-once retry and outcome-unknown behavior.
- Revocation delivery semantics.

Then add an optional `nq-wlp-adapter` depending on NQ core and WLP, never the reverse. Preserve two identities:

- Inner NQ evidence digest: semantic report identity.
- Outer WLP artifact hash: custody-envelope identity.

The future result chain remains:

```text
transport error
→ WLP recorded or envelope-refused
→ NQ admitted or semantically refused
```

A custody ACK means only “durably recorded.” It never establishes NQ profile admission, a claim, standing, or authority. Raw TCP versus HTTP remains a WLP decision after framing and durability are ratified, not an nq-ng v1 assumption.

## Test and Acceptance Plan

- Protocol corpus covers exact version pinning, request IDs, framing, deadlines, extra stdout, stderr bounds, EOF/exit/disconnect distinctions, malformed/duplicate JSON, oversize frames, capability and scope escape, checkpoint behavior, and clean persistent-helper restart.
- Process tests prove output larger than pipe capacity completes or fails `output_too_large`, never masquerades as timeout.
- Admission tests cover symlink/path replacement, script/interpreter chains, profile mismatch, binary drift, config drift, atomic rotation, rollback verification, and stale-lock quiescing.
- Profile tests cover strict vocabularies, complete disjoint coverage, field/coverage consistency, subject identity, bounds, partial/failed reports, freshness, regime/scope limitations, and negative overclaim fixtures.
- Storage tests prove exact raw retention, canonical digest stability, unknown-profile quarantine, two same-profile instances, immutable renewal, rejected evidence isolation, crash consistency, retention tombstones, and rebuildable projections.
- Detector/lifecycle tests prove missing evidence cannot clear, old successful evidence cannot shadow a newer failure, only sufficient current coverage can resolve, multi-witness composition is explicit, and every finding carries exact evidence/profile/detector revisions.
- API/CLI/console contract tests consume the same read model and render failed, refused, stale, empty, and healthy states distinctly.
- Nightshift and blackbox integration tests use public CLI/API/sample surfaces and forbid direct NQ database access.
- Install tests cover clean package install, initialization, permission checks, helper admission, backup/restore, failed and successful upgrades, uninstall versus purge, and start refusal on schema mismatch.
- Cutover tests verify the legacy manifest and exports, new genesis reference, and absence of imported active state.

The decisive extensibility tests are:

1. Add a second implementation of an existing profile in Python with only config/admission changes.
2. Add a new fixture profile by changing only its profile module, fixtures/helper, and one registry entry.
3. Confirm neither operation edits core scheduling, batch types, storage publication, central enums/matches, API special cases, or base migrations.

### Assumptions

- Linux/systemd and SQLite are the supported v1 platform.
- Local Unix IPC and loopback console only; no remote administration or fleet auth.
- Request/response helpers only; no asynchronous streams.
- Rust is the only supported SDK in v1.
- No dynamic plugins, semantic DSL, EAV ontology, or runtime-defined detectors.
- No legacy data importer or compatibility mode.
- Claims, inquiry, WLP transport, remote enrollment, and action authority remain outside the operational-core release.

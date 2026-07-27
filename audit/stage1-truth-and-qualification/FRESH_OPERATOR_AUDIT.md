# Fresh-operator installation and first-use audit

Audit date: 2026-07-27

Authority: none.

Scope: NQ Classic, NQ-NG, `nq-witness`, `nq-blackbox`, and relevant checked-in
Labelwatch and Driftwatch deployment material.

Method: repository-first, read-only evaluation without using prior assistant
deployment memory or private operator history.

## Claim classes

- **Observed** means verified from the current local filesystem, executable
  help, package contents, or the separately recorded live `sushi-k` census.
- **Repository claim** means a checked-in document describes the behavior; it
  is not treated as proof that a release asset or deployment exists.
- **Inferred** means a bounded operator-experience conclusion supported by
  observed material.
- **Unknown** means the audit did not establish the fact.

This audit evaluates whether a new operator can reach a meaningful, honest
result. It does not select a new architecture, authorize deployment, or ratify
a package/repository topology.

## Corrected ownership frame

The candidate successor boundary used by this audit is:

```text
witness/provider acquisition
  gathers bounded testimony with exact identity, scope, and custody
        ↓
one NQ diagnostic
  selects exact required evidence; checks custody, admissibility, and coverage;
  evaluates one scoped, bounded subject and question; returns a typed
  disposition or refusal; may use child NQ testimony for that same question
        ↓
Nightshift operations
  schedules recurrence, applies expiry, coordinates campaigns, and composes
  multiple exact diagnostic results and context into a current posture
        ↓
monitoring / alerting / portraits / reporting / proposed automation
  built from typed diagnostics and Nightshift posture; Maude or another
  frontend renders the operator experience
```

NQ-to-NQ recursion is a light testimony fabric, not open-ended operational
composition. A child disposition or refusal remains bounded by its exact
subject, question, evidence frontier, and limitations and may be consumed only
for the same exact parent diagnostic question. The primary NQ object is one
diagnostic; repeating diagnostics under Nightshift is what monitoring is built
on. Nightshift owns recurrence, expiry, campaigns, and multi-diagnostic current
posture. Humans or agents own operational judgment; AG/Docket own governed
authority and execution. NQ must offer a stable typed diagnostic read/export
contract. `nq-monitor` is at most an inspector/disposition explorer; the
whole-estate profile/posture surface belongs to Nightshift output, rendered by
Maude or another frontend.

Classic NQ Monitor remains an observed deployed product surface and
functional-equivalence input. This ownership correction does not erase or
reinterpret that fact.

## Result

Neither Classic nor NQ-NG currently offers a complete normal-operator
production path.

Classic has broader operational functionality and a usable no-root
quickstart, but its documented release path is blocked, so a durable install
requires a pinned Rust source build followed by substantial manual system
assembly. The actual `sushi-k` deployment diverges from that documented
production layout and cannot be reconstructed from checked-in material alone.

NQ-NG has the stronger reproducible package and lifecycle foundation, but the
package intentionally stops before configuration, initialization, helper
admission, validation, enablement, or startup. Its first useful host result is
also much narrower than Classic's. A literal operator must execute a lengthy
capability-bearing maintenance recipe before the daemon can start.

The application repositories expose useful semantic progress information, but
their checked-in deployment material is inconsistent or incomplete and generic
HTTP 2xx checks do not consume their semantic verdicts.

## Normal-operator acceptance questions

The audit used these result-oriented questions. They do not prescribe an
implementation shape.

1. Is there one identified, checksummed install artifact containing every
   required runtime and deployment file?
2. Can an operator identify the intended host/application role without reading
   source code or historical memory?
3. Does installation preserve existing state and fail visibly when a choice is
   required?
4. Can the operator create and validate configuration without retyping an
   undocumented schema?
5. Can the first start produce a useful, bounded host result without a
   developer checkout?
6. Are omitted, unavailable, and refused coverage visibly distinct from
   healthy absence?
7. Are upgrade, backup, rollback, notification delivery, and removal behavior
   explicit?
8. Can literal documented commands be exercised against the installed binary
   version?

## NQ Classic

### Observed and repository-backed strengths

- The current quickstart gives a no-root loopback trial with two binaries,
  checked-in configs, an evidence database, web/API/SQL inspection, and an
  explicit statement of what the trial does not prove.
- The production guide covers service identities, directory ownership,
  collector privileges, network boundaries, backup, upgrade, and rollback.
- Classic has broad executable collection and detection families relative to
  NQ-NG: host, services, SQLite, WAL, logs, Prometheus, ZFS, SMART, GPU, finding
  lifecycle, notifications, and operator read surfaces.
- Current documentation explicitly warns that no-auth/no-TLS HTTP surfaces
  should remain on loopback or a private/VPN boundary.

### Blocking friction

- Current Classic documentation records an HTTP 404 for the advertised
  `nq-monitor` release asset and states that no release bundle contains all
  decomposed binaries, configurations, and service files. This is a repository
  claim from its clean-room audit, not an independently repeated network check
  in this stage.
- The supported fallback is a pinned Rust source build. That requires a
  compiler/toolchain and a reviewed source archive before deployment can
  begin.
- Durable production assembly remains manual: matched binaries, accounts,
  directories, modes, configs, collector permissions, two services, firewall
  or tunnel boundaries, backup, and upgrade procedure.
- Target selection is hand-authored. There is no host-role discovery or
  authoritative intended-coverage manifest.
- The actual `sushi-k` units use a developer checkout's `target/release` and
  home-local configuration instead of the documented production layout.
- The deployed sushi-k build predates current documented CLI validation
  commands. Version/docs mismatch fails literal first contact.
- Live configuration and user units are not packaged or checked in, so a
  second operator cannot reproduce the deployed result from the repository.

### Fresh-operator verdict

**Trial:** possible from reviewed source.

**Production:** not a normal package install.

**Reproduction of sushi-k:** not possible from checked-in material alone.

**First useful breadth:** broader than NQ-NG once manually configured.

## Supporting Classic repositories

### `nq-witness`

Observed repository state:

- It is a draft, language-neutral supporting-protocol specification
  repository, not the Classic `nq-witness` binary despite the shared name.
- It has four profiles but only two Python reference exporters.
- It has no shared SDK, package, service unit, privilege installer, or complete
  production playbook.
- The filesystem-inode and Kea DHCP profiles are specifications without
  implementations.
- The SMART helper documents a required NOPASSWD wrapper in source comments,
  but no installer materializes that privilege boundary.

Inferred friction:

- The naming collision is likely to confuse first contact.
- Copying a helper path into config does not establish a working deployment;
  executable placement, privilege, timeout, coverage, and standing still need
  explicit assembly.
- Sushi-k demonstrates the resulting path-drift failure.

### `nq-blackbox`

Observed repository state:

- It explicitly identifies itself as an integration lab rather than a
  product.
- It does not vendor `blackbox_exporter` or ship a service unit/installer.
- Targets are declared manually; there is no discovery.
- It feeds Prometheus-shaped samples to Classic but intentionally does not
  create automatic claims or alerts from `probe_success`.
- Only `http_2xx` and one DNS module are checked in; sushi-k promotes one local
  NQ self-probe.

Inferred friction:

- A fresh operator must independently obtain and supervise the exporter, then
  translate target catalog entries into NQ configuration.
- A successful smoke probe establishes an acquisition path, not application
  health or alert delivery.
- Bare metric series identity currently limits safe multi-target promotion in
  the checked-in local catalog.

## NQ-NG

### Observed strengths

- The release assembly can produce a Debian package and tarball with checksums,
  `nq`, `nqd`, the native host helper, systemd/sysusers/tmpfiles material,
  examples, compiled profiles, and conformance assets.
- Package lifecycle is deliberately conservative: identity and empty
  directories are created, configuration and durable state are preserved, and
  package install does not silently initialize, migrate, enable, or start.
- The service unit checks installed bytes and configuration before startup and
  applies a substantial sandbox.
- The operator CLI exposes explicit config, init, admission, doctor, backup,
  restore, status, finding, evaluation, refusal, and query surfaces. These are
  current read surfaces, not yet a ratified stable diagnostic export contract.
- The local Unix API is enabled while the loopback HTTP console is off by
  default.

### Blocking friction

Package installation intentionally leaves all of these steps to the operator:

1. locate and copy an example configuration;
2. review and replace its nonce;
3. run `config check`;
4. initialize the database;
5. define a roughly 35-line `systemd-run` shell function that mirrors the
   daemon's capability and sandbox boundary;
6. test the watcher;
7. admit the watcher;
8. run `doctor`; and
9. enable and start `nqd`.

Additional first-contact problems:

- The main walkthrough begins with the Python conformance specimen. The native
  host example is introduced later as an alternative, so literal execution can
  yield a protocol demonstration rather than the expected bounded host
  diagnostic.
- Plain `sudo -u nq` is insufficient for test, admission, collection, and
  doctor; the operator must understand and preserve the transient-unit
  capability boundary.
- Current NQ-NG host testimony is only hostname, uptime, CPU count, and
  one-minute load. It lacks Classic memory, root-capacity, service, storage,
  log, and sample-lane breadth.
- Notifications, retention automation, historical migration breadth,
  DNS/TLS/reachability, remote enrollment, and fleet operation are explicitly
  absent.
- Package upgrade stops the service and leaves validation and restart to the
  operator.
- `/usr/bin/nq` conflicts with Debian's unrelated `nq` package; no
  side-by-side executable name is provided.
- Current main is unpublished, untagged after `v0.1.0`, and undeployed.

### Fresh-operator verdict

**Artifact quality:** materially stronger than Classic.

**First-start workflow:** too manual for an ordinary host install.

**First useful breadth:** insufficient to replace sushi-k.

**Safety posture:** strong fail-closed behavior, but operator ceremony is part
of the current product surface and must itself be qualified.

## Application deployment and semantic monitoring

The following are repository observations only. This audit did not infer live
Linode state from them.

### Labelwatch

- The README describes three systemd services and one SQLite database.
- `deploy/README.md` installs only the main service plus nginx even though API
  and discovery units are present in the directory.
- The deployment guide explicitly leaves HTTPS, log rotation, database
  bounding, and notification delivery to the operator.
- The development quickstart uses `pip install -e`, not an immutable production
  artifact.
- README schema prose says v21 while its architecture diagram says v19.
- `/health` always returns HTTP 200 and `"ok": true`, then embeds independent
  read-health and signal-health verdicts. `http_2xx` cannot detect their
  degraded states.
- Labelwatch reports useful application progress: discovery, ingest, scan,
  derive, report and stream heartbeats, signal classifications, read success,
  and facts-bridge coverage.
- Classic's `nq-check-pack-labelwatch` is a typed collection plan, not an
  executable collector. It has no application-specific target or threshold
  defaults and does not consume these progress semantics.

Fresh-operator consequence: deploying the checked-in main service is not the
same as deploying the documented three-service application, and generic
service/HTTP testimony is insufficient for meaningful health.

### Driftwatch

- Production material is one Docker Compose service bound to loopback port
  8422 with data/output bind mounts.
- The Compose healthcheck calls the trivial `/health`, which always returns
  `{"status":"ok"}`.
- The production quickstart says to copy `deploy/.env.example`, but that file
  is absent; `deploy/.env.prod.example` exists.
- The deploy script rsyncs source with `--delete`, rebuilds remotely, restarts,
  and accepts simple `/health`. It does not provide an immutable image pin,
  atomic switch, or automatic rollback.
- `/health/extended` exposes build, emit mode, queue/cursor progress, platform
  health, coverage, event rate, lag, reconnects, drops, WAL, resolver progress,
  facts-export freshness, disk pressure, and optional retention state.
- `/health/preflight` and `/health/bake` return semantic verdicts in JSON, but
  current route code does not change HTTP status for FAIL/BAD. This contradicts
  the README's preflight-503 claim.
- Admin endpoints are open if no admin token is configured.
- Retention, maintenance, facts export, and longitudinal rechecks are
  separately disabled by default.

Fresh-operator consequence: simple container health and HTTP 2xx can stay
green while the application is semantically degraded, unbaked, stalled, out
of coverage, or running with important loops disabled.

## First useful result comparison

| Path | What a literal fresh operator obtains | What remains unproven |
|---|---|---|
| Classic quickstart from source | Basic host snapshot, loopback witness/monitor path, DB, UI/API/SQL | Production identity, full role coverage, notifications, backup, external reachability |
| Classic production guide | A possible manually assembled two-service install | Reproducible release artifact and match to sushi-k |
| NQ-NG package plus conformance sample | Protocol/admission demonstration after extensive setup | Useful host portrait |
| NQ-NG package plus host sample | Hostname, uptime, CPU count, load, typed custody/refusal | Memory, capacity, services, applications, storage, logs, notifications |
| Labelwatch deploy README | Main loop and static nginx output | Discovery/API parity, HTTPS, bounded DB, notification, semantic monitoring |
| Driftwatch Compose | One container whose simple liveness is checked | Extended semantic health, bake/preflight verdict, feature enablement, rollback |

## Candidate finding: independent notification-delivery facet

**Status: candidate for evaluation only. It is not ratified architecture.**

### Observed problem

- Sushi-k has notification eligibility set to warning but zero configured
  channels.
- Classic supports transports but treats delivery as best effort and does not
  provide a durable delivery queue.
- NQ-NG stores disposition/evaluation state and notification outbox/attempt
  tables but has no notification delivery worker. Those tables are
  unratified scaffolding, not a selected notification contract.
- A successor cut can therefore preserve monitoring semantics while silently
  losing the operator's expected delivery path.

### Candidate boundary

Evaluate notifications as an independent **`nq-notify` delivery facet** that:

- consumes an exact alert intent created by Nightshift or explicit
  operator policy for an identified diagnostic or operational state
  transition, with every NQ disposition or refusal identity that informed it;
- preserves diagnostic-output, state-transition, alert-intent, and policy
  identities;
- attempts delivery without gaining authority to create alert intent
  or change the NQ disposition/refusal;
- records durable delivery receipts or explicit failed/refused attempts; and
- exposes enough receipt state for an operator to distinguish “no alert
  intent,”
  “not attempted,” “attempted,” “delivered,” “failed,” and “unknown,” if and
  only if those states are later specified and versioned.

The last bullet names questions the facet must close; it does not ratify those
state names as a schema.

### What this candidate does not decide

This finding does **not** decide:

- whether `nq-notify` is a repository, crate, binary, daemon, package, library,
  queue consumer, or in-process worker;
- which transports exist;
- which diagnostic or operational state transitions create alert intent;
- recipient, routing, suppression, retry, backoff, deduplication, ordering,
  escalation, or retention semantics;
- whether delivery is at-most-once, at-least-once, or another explicitly
  bounded contract;
- whether a receipt proves human attention; or
- whether notification failure changes NQ's underlying finding or disposition
  (it must not).

No such semantics may be inferred from the facet name.

A raw NQ finding, evaluation, disposition, or refusal does not automatically
page. NQ owns the exact diagnostic result. Nightshift and operator policy own
alert intent for an exact diagnostic or operational state transition. The
candidate facet owns only delivery and attempt/result receipts.

### Qualification questions before any ratification

1. What exact typed NQ disposition/refusal carrier informs the alert intent,
   and how is its semantic identity preserved?
2. What exact diagnostic or operational state transition occurred, and what
   versioned Nightshift/operator policy creates alert intent and binds a
   route?
3. What constitutes an attempt, transport acceptance, durable delivery
   receipt, explicit refusal, and unknown outcome?
4. How are policy changes, replay, duplicate transport responses, crashes, and
   partial failures represented without mutating NQ evidence?
5. What does backup/restore preserve, and what state must never be replayed
   automatically?
6. Which operator surface exposes delivery coverage and silence?
7. Which end-to-end fixture proves an exact alert intent for an identified
   transition can reach a receiver and leave an inspectable receipt?

Until these are answered and separately qualified, `nq-notify` remains a
candidate capability boundary, not an implementation or cutover claim.

## Inferred cross-project findings

1. The primary install gap is not lack of documentation volume. It is the lack
   of one version-matched artifact and bounded workflow from install to a
   meaningful declared role.
2. NQ-NG's non-destructive package policy is a sound safety property, but the
   current manual ceremony is not yet a normal-person deployment experience.
3. Classic has more operational breadth, but the sushi-k deployment shows that
   hand-maintained home paths and optional helpers drift.
4. Application-native semantic endpoints already contain stronger progress
   testimony than generic systemd, Docker, or HTTP 2xx checks.
5. A successor should consume those bounded application semantics through
   compiled profiles rather than infer health from liveness.
6. Notification delivery is an independently lossy boundary and should not be
   hidden inside NQ evaluation, confused with Nightshift/operator alert intent,
   or inferred from transport configuration.
7. The observed Classic dashboard does not make whole-estate dashboard UX an
   NQ successor responsibility. `nq-monitor` is an inspector/disposition
   explorer; the stable target is typed NQ export plus a Nightshift surface
   showing profiles, last-result time/applicability/coverage/expiry, and
   current posture, consumed by Maude or another frontend.

## Unknowns

- The minimum role-complete host portrait that the operator requires.
- Whether a no-root trial, system package, container, configuration manager, or
  another installation surface is required for the first supported release.
- Exact live Labelwatch and Driftwatch service/configuration state.
- Required notification transports, recipients, policies, and guarantees.
- Required history, backup, upgrade, and rollback windows.
- The stable typed NQ diagnostic export/inspector contract, Nightshift
  recurrence/expiry/profile/posture contract, and frontend acceptance tasks.
- Whether Classic and NQ-NG must coexist on one host during qualification.
- Which application-native semantic verdicts are stable enough to compile into
  a versioned profile.

These choices must be supplied or ratified separately. The audit does not
resolve them by choosing a repository or package shape.

## Acceptance target for a future fresh-operator qualification

A future candidate should be tested from a clean, supported host using only
the candidate artifact and its literal documentation. The receipt should show:

- exact artifact identity and checksum;
- no sibling checkout or developer `target/` dependency;
- explicit role and coverage declarations;
- config validation before state creation;
- first useful host/application result;
- visible unavailable/refused/omitted coverage;
- stable typed diagnostic export/inspection and Nightshift profile, last
  result, applicability, coverage, expiry, and current-posture output usable by
  a frontend without private-table reconstruction;
- service state after install and after an upgrade attempt;
- backup and rollback behavior;
- notification-delivery coverage or an explicit declaration that none exists;
  and
- no authority switch merely because the trial succeeded.

This is an acceptance outcome, not a decision about installer technology,
repository layout, daemon count, or package composition.

## No-mutation record

The audit used filesystem/source reads, executable help, package-content
inspection, Git metadata, and the separately recorded read-only sushi-k
evidence. It did not build, test, install, deploy, start, stop, restart,
enable, disable, reload, migrate, edit configuration, alter a database,
contact a remote host, commit, or push.

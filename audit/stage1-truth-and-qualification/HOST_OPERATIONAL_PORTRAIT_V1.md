# Host Operational Portrait v1 — candidate ratification draft

| Field | Value |
|---|---|
| Status | `candidate_for_operator_ratification` |
| Authority | `none` |
| Portrait version | 1 |
| Subjects | `sushi-k`; `labelwatch.neutral.zone` with logical NQ identity `labelwatch-host` |
| Machine companion | `DEPLOYED_CAPABILITY_MANIFEST.json` |
| Audit date | 2026-07-27 |

## Authority boundary

This document is a candidate interpretation of two read-only deployed
censuses. It is not a ratification record, deployment plan, release
qualification, health verdict, authority switch, service inventory closure, or
permission to change a host.

In this draft:

- **observed** means a named census directly established the deployed state;
- **required** means a candidate Host Operational Portrait v1 obligation that
  becomes binding only if an operator ratifies it;
- **retire** means a candidate may be permitted to retire only after an
  explicit operator decision and the recorded replacement or no-obligation
  condition; and
- **owner-decision** means the census cannot choose the inventory, threshold,
  baseline, policy, recipient, duration, or retirement disposition.

A row may carry multiple classifications. For example, a service collector can
be both observed and candidate-required while its exact closed inventory
remains an owner decision. Merging or committing this draft does not ratify any
row.

## Diagnostic product frame

The candidate ownership stack is:

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

The primary NQ object is one diagnostic, not an estate monitor or continuous
posture. Repeating diagnostics under Nightshift is what monitoring is built
on. Nightshift owns recurrence, expiry, campaigns, and multi-diagnostic
operational posture. Humans or agents make operational judgments; AG/Docket
own any governed authority and execution. Maude or another frontend owns
presentation.

NQ-to-NQ recursion remains useful as a light testimony fabric: one NQ
diagnostic may consume an exact bounded disposition or refusal from another
NQ diagnostic without laundering its subject, question, evidence frontier, or
limitations. Recursion does not turn NQ into an open-ended operations
composer.

Candidate portrait-level operational question:

> What operational conditions and evidence limits are current for the
> diagnosed subject across its declared host and application scope, what
> contradictions or shared failure domains matter, and what safe next checks
> are supported?

That portrait question is not one NQ diagnostic. It decomposes into an
operator-ratified catalogue of bounded diagnostic profiles. Nightshift binds
their exact results, applicability, expiry, and coverage into the current
portrait.

The roles are distinct:

| Role | Responsibility |
|---|---|
| Witnesses and providers | Gather and submit admitted testimony with exact subject, scope, vantage, identity, capability, and custody boundaries |
| Profiles | State one compiled, identified diagnostic question, evidence projection, coverage, bounds, limitations, and evaluator semantics |
| NQ | Select exact required evidence; check custody, admissibility, and coverage; evaluate one scoped, bounded subject/question; emit an exact typed disposition or refusal |
| Recursive NQ testimony | Carry an exact child disposition or refusal as bounded testimony for the same exact parent question; never broaden it into operational composition |
| `nq-monitor` | Inspect one diagnostic's evidence, custody, coverage, evaluation, disposition, and refusal; it is not the whole-estate console |
| Nightshift | Own recurrence, expiry, campaigns, multi-diagnostic posture, reporting inputs, and operational proposals without rewriting NQ testimony |
| Humans and agents | Provide separately identified operational interpretation or proposals; their output is not NQ testimony or action authority |
| Monitoring, alerting, and portraits | Derive change, current posture, alert intent, and reports from repeated exact diagnostics and Nightshift state |
| Human or AG authorization | Own separately governed authorization for an operation |
| Docket | Execute only through the separately governed operation boundary |
| Maude or another frontend | Render stable typed NQ diagnostic exports and Nightshift operational output; presentation does not mint diagnostic or operational authority |
| Alert intent | Nightshift or explicit operator policy records an exact diagnostic or operational state transition that warrants delivery |
| Candidate notification delivery | `nq-notify` attempts delivery and retains attempt/result receipts without choosing alert intent or changing the diagnostic output |

A provider, witness, profile, detector, diagnostic read/export path,
Nightshift recurrence/campaign, or frontend view can contribute to the operator
journey but is not the whole ownership stack. Host Operational Portrait v1 is
the candidate minimum complete operational-posture contract across each
ratified subject, scope, vantage, operator task, diagnostic profile,
application overlay, self-diagnosis, stable typed read/export, recurrence,
expiry, alerting, retention, backup, and clean-install obligation.
Nightshift composes that posture from bounded NQ results; NQ does not produce
the whole portrait.

The operator's MRI comparison is only an analogy about the difference between
acquisition and one scoped diagnostic. It does not introduce medical
terminology, medical claims, or medical semantics into NQ.

## Evidence identity

| Evidence file | SHA-256 | Role |
|---|---|---|
| `SUSHI_K_CENSUS.md` | `147d5c89e93488b182afbd521c6b1191b99efb9241f4ba72388559e71ef394cb` | Primary live sushi-k census |
| `LINODE_CENSUS.md` | `0a79b82c39d76ff2c86a6021de4d0e1da82c1aa1098b1f1e1cdb747ff31852dc` | Primary live Linode census |
| `FRESH_OPERATOR_AUDIT.md` | `0aeb43ddcb3c9974d2054d7bf55d6ddbb03f79df86d6b808ac64264645da9921` | Supporting install and notification-boundary audit |
| `NOTIFICATION_FACET_CANDIDATE.md` | `32c0c32dde151b112bc5b5cd2966f0b7694de589f174639d298d4dda24f1cad8` | Supporting unratified notification-boundary and falsification record |

The JSON companion binds the same paths and digests. Repository examples,
current source, and historical campaign prose do not replace these live
records.

## Diagnosed subject identity

| Diagnosed subject | Observed host identity | NQ identity | Important boundary |
|---|---|---|---|
| `sushi-k` | static hostname `sushi-k` | source and instance `sushi-k` | User-local Classic deployment in a mutable developer checkout |
| `labelwatch-host` | DNS locator `labelwatch.neutral.zone`; static hostname `localhost` | source and instance `labelwatch-host` | Logical identity is explicitly configured and must not be replaced by `localhost` |

The Linode locator and logical subject name are two identifiers for one
portrait subject. They are not two independent hosts or vantages.

## Candidate coverage and outcome taxonomy

Coverage and condition are separate axes.

### Acquisition and coverage

| State | Candidate meaning |
|---|---|
| `current` | Required evidence arrived within its bound and was admitted for the exact subject, scope, and vantage |
| `partial` | Some required subjects, fields, dimensions, or vantages are current and others are unavailable or unaccounted for |
| `stale` | Previously accepted evidence exists but is older than its bound |
| `refused` | Acquisition, admission, projection, or evaluation explicitly refused and retained its boundary |
| `missing` | Evidence was expected under an explicit inventory but did not arrive |
| `unsupported` | The qualified provider or profile explicitly cannot testify about the substrate or dimension |
| `intentionally_excluded` | An operator-ratified scope declaration excludes it; silence cannot create this state |
| `not_configured` | No target or provider is declared; this is not healthy absence |

### Domain condition

| State | Candidate meaning |
|---|---|
| `condition_present` | Current sufficient evidence supports the bounded condition |
| `explicitly_absent` | Current sufficient evidence under closed declared coverage supports bounded absence |
| `unknown` | Evidence is insufficient, inapplicable, contradictory, or not evaluated |

### Evidence relations within one diagnostic

Evidence from application, systemd or Docker, storage, local HTTP, proxy, and
external-vantage surfaces may agree, contradict, share a failure domain, have
unknown independence, or remain uncompared. Agreement does not erase their
separate scopes.

These rules follow:

1. Collector success with zero rows does not close an inventory.
2. An empty configuration is `not_configured`, not green.
3. A stale, silent, or refused witness cannot establish healthy absence.
4. Service or container up does not establish application progression.
5. HTTP 2xx does not establish a semantic application verdict.
6. Classic NQ Monitor loop liveness does not mean the diagnosed subject is
   healthy.
7. Missing Prometheus series remains not observed unless an independent
   closed-world inventory supports more.

## Common candidate portrait sections

Every ratified diagnosed subject would need each required section to expose both
coverage and condition:

1. observation currency, expected coverage, and NQ self-observation;
2. subject identity, boot epoch, kernel, uptime, and relevant clock basis;
3. CPU/load/pressure and memory/swap/pressure;
4. in-scope filesystems, mounts, byte and inode capacity, read-only state, and
   backing-device relationships;
5. required service, container, and process lifecycle plus recent changes;
6. interfaces, routes, listeners, proxies, and explicitly bounded local or
   external reachability;
7. required device or storage state;
8. bounded logs, events, database metadata, WAL state, and qualified
   Prometheus or blackbox intake;
9. application-owned phase, progression, publication, export, coverage, and
   consumer-visible state;
10. contradictions, shared failure domains, missing evidence, limitations, and
    safe next checks;
11. Nightshift recurrence, expiry, campaign state, and self-diagnosis;
12. a stable typed NQ diagnostic read/export contract, including exact
    disposition and refusal identity;
13. Nightshift operational output that binds the diagnostic inputs it
    composes, exposes profiles and each last result's time, applicability,
    coverage, and expiry, and can be rendered by Maude or another frontend;
14. alert intent, attempt, and delivery-receipt coverage across the
    Nightshift/operator-policy and candidate `nq-notify` boundary;
15. retention, disk runway, backup, restore, and historical archive state; and
16. clean installation, upgrade, rollback, and removal behavior.

The exact required subject inventories and semantic thresholds remain open
where marked owner-decision below.

## Operational portrait: `labelwatch-host`

### Observed deployment summary

- Ubuntu 22.04.5 LTS, kernel 5.15.0-171, static hostname `localhost`.
- Classic schema 64, one logical source `labelwatch-host`, 60-second cadence.
- NQ publisher on loopback `127.0.0.1:9847`; Monitor on `0.0.0.0:9848`.
- Deployed binary hashes are recorded in the manifest. The dirty source tree
  is not product authority.
- Fourteen configured service targets were up at the captured generation:
  `caddy`, `driftwatch`, `gov-webui`, `governor`, `governor-bridge`,
  `labelwatch`, `labelwatch-api`, `labelwatch-discovery`,
  `labelwatch-lock-watcher`, `nq-publish`, `pds`,
  `postgresql@15-main`, `postgresql@17-main`, and `receipts-feed`.
- Four SQLite metadata paths were configured; three were current and
  `facts_work.sqlite` was not represented.
- Three WAL targets, four journald targets, and two Prometheus target families
  were configured.
- ZFS, SMART, and GPU collectors were skipped.
- Slack and Discord transports were configured and historic notification rows
  existed, but delivery guarantees were not established.
- Retention was 2,880 generations with pruning every 60 cycles. The main NQ DB
  was about 135 MB while the configured budget was 100 MB; enforceability was
  unknown.

### Candidate capability classification

| Portrait area | Observed state | Classifications | Candidate result or unresolved decision |
|---|---|---|---|
| Observation currency | One source current in a 60-second loop | observed, required | Preserve exact source identity, attempt/completion, freshness, and missed/refused cycles |
| Expected coverage | No coverage rules | observed, required, owner-decision | Ratify the complete service, storage, network, telemetry, and application inventory |
| Host identity and time | Logical identity, boot, kernel, uptime present; relevant clock basis incomplete | observed, required | Preserve logical identity separately from `localhost`; add bounded time basis |
| CPU/load/pressure | 1m/5m load present; no complete CPU utilization or PSI | observed, required, owner-decision | Select dimensions, thresholds, and baseline ownership |
| Memory/swap/pressure | total, available, and derived pressure present; swap/PSI incomplete | observed, required, owner-decision | Select required swap and pressure semantics |
| Filesystems/mounts | Root capacity and scoped mount relationships observed; no closed per-mount/inode portrait | observed, required, owner-decision | Ratify mount inventory, exclusions, bytes, inodes, read-only state, thresholds, and runway |
| Shared storage/device | Root and `/dev/sdc` relationships observed; device health absent | observed, required, owner-decision | Preserve shared-failure-domain evidence; decide SMART/device-health obligation |
| Services/processes | Fourteen configured targets current | observed, required, owner-decision | Decide whether those targets close the required inventory and define recent-change semantics |
| Network/reachability | Relevant listeners and Caddy presence observed; interfaces, routes, DNS/TLS and vantage closure absent | observed, required, owner-decision | Ratify exact network inventory and required vantages |
| SQLite metadata | Three of four configured paths current | observed, required, owner-decision | Classify `facts_work.sqlite`; close the DB inventory; keep file testimony separate from query correctness |
| SQLite WAL | Three explicit targets current | observed, required, owner-decision | Close WAL inventory and bind thresholds/incorporation semantics |
| Logs | Four journald sources current | observed, required, owner-decision | Close important-log inventory and distinguish quiet, missing, denied, parse error, stale, and condition |
| Prometheus/blackbox | `node` and external-HTTP families current | observed, required, owner-decision | Qualify provider identity and partial/warning semantics; decide independence and retained families |
| Labelwatch overlay | Generic service, DB/WAL, log, and metrics only | observed, required, owner-decision | Admit application-owned progression and publication testimony |
| Driftwatch overlay | Container and selected DB/WAL state only | observed, required, owner-decision | Admit application-owned ingest, lag, loss, gate, storage, retention, and export testimony |
| Other application overlays | Generic lifecycle observed | observed, required, owner-decision | Decide which other declared services need semantic overlays |
| NQ and Nightshift self-diagnosis | Source loop and binary observation exist; exact source identity and budget enforcement incomplete | observed, required | Expose NQ build/cohort, provider/admission/store/export plus Nightshift recurrence/expiry/campaign/posture and alert-delivery state |
| Operator read surface | Classic NQ Monitor surface exists | observed, required | Preserve that live fact while replacing the successor target with the common typed diagnostic read/export and operational-presentation obligations below |
| Notification delivery | Transports and history observed; delivery contract unknown | observed, required, owner-decision | Ratify Nightshift/operator state-transition and alert-intent policy, recipients, delivery meanings, and `nq-notify` receipt obligation through the candidate seam |
| Retention/backup | Retention configured; budget discrepancy measured; backup obligation unknown | observed, required, owner-decision | Ratify periods, backup/restore objectives, and budget enforcement |
| Clean install | No installed NQ package or Rust toolchain; binaries copied under `/opt/notquery` | observed, required | Produce a clean, verified, useful host-role result without remote compilation |
| Classic runtime | Deployed authority | observed, retire | Retire only after independent equivalence, explicit switch, archive, and rehearsed rollback |

No row declares the observed service or target list complete. That closure is
an owner decision.

## Operational portrait: `sushi-k`

### Observed deployment summary

- Classic build identity `361c5cdfa491`, schema 64, one source `sushi-k`,
  60-second cadence.
- User services execute mutable checkout `target/release` binaries with
  home-local configs and state.
- Six configured services: `cron`, `gnome-remote-desktop`,
  `governor-code-adapter`, `rsyslog`, `smartmontools`, and `ttyd`.
- Five systemd subjects were up. Docker target `governor-code-adapter` was
  down.
- Host and NQ-binary collectors were current.
- No SQLite metadata, WAL, or log targets were configured.
- One local blackbox target probed the NQ Monitor itself.
- ZFS and GPU were not configured.
- SMART was configured but refused collection because its helper path had
  drifted.
- Five active critical findings represented the down service, failed saved
  checks, and unavailable SMART testimony.
- Retention was 2,880 generations with pruning every 60 cycles. The configured
  200 MB budget was declarative only.
- Notification threshold was warning with zero channels.

### Candidate capability classification

| Portrait area | Observed state | Classifications | Candidate result or unresolved decision |
|---|---|---|---|
| Observation currency | Source current in a 60-second loop | observed, required | Preserve exact source identity, attempt/completion, freshness, and missed/refused cycles |
| Expected coverage | No coverage rules or operational-intent declarations | observed, required, owner-decision | Ratify the complete host, service, storage, network, log, and application inventory |
| Host identity and time | Basic identity, boot, kernel, uptime present | observed, required | Add relevant bounded time basis |
| CPU/load/pressure | Load present; CPU utilization/pressure incomplete | observed, required, owner-decision | Select dimensions, thresholds, and baseline ownership |
| Memory/swap/pressure | Total, available, and derived pressure present; swap/PSI incomplete | observed, required, owner-decision | Select required swap and pressure semantics |
| Filesystems/mounts | Root byte capacity only | observed, required, owner-decision | Ratify complete mount inventory, bytes, inodes, read-only state, thresholds, and runway |
| Services/processes | Six configured targets; one down | observed, required, owner-decision | Decide whether six close the inventory; preserve current condition and recent changes |
| `governor-code-adapter` | Declared Docker target down | observed, retire, owner-decision | Explicitly retain/repair and define overlay, or explicitly retire |
| Network/reachability | Only local NQ self-probe; no host network portrait | required, owner-decision | Ratify interfaces, routes, listeners, endpoints, DNS/TLS, and external-vantage obligations |
| SQLite metadata/WAL | Zero targets | observed, owner-decision | Declare required application DB/WAL inventory; absence remains not configured |
| Logs | Zero targets | observed, required, owner-decision | Declare important log sources; absence remains not configured |
| Local blackbox self-probe | Current HTTP 2xx testimony for NQ Monitor | observed, retire, owner-decision | Preserve as a named facade vantage or explicitly replace/exclude it |
| SMART | Configured helper path missing; testimony refused | observed, retire, owner-decision | Explicitly repair/require with bounded privilege and device inventory, or retire |
| ZFS/GPU | Not configured | observed, owner-decision | Declare whether either substrate exists and is required |
| NQ and Nightshift self-diagnosis | Liveness and binary observation present; CLI/docs drift and active collector failure exist | observed, required | Expose NQ version/cohort, helper/admission/store/export plus Nightshift recurrence/expiry/campaign/posture and alert-delivery state |
| Operator read surface | Classic NQ Monitor surface exists and current critical facts exist | observed, required | Preserve that live fact; require the successor typed export and consuming frontend to lead with supported facts rather than turn loop liveness into all-clear |
| Notification delivery | No channels configured | observed, required, owner-decision | Decide whether Nightshift/operator alert intent and delivery are required, then ratify receiver, transport, and receipts |
| Retention/backup | Approximately 48 hours configured; backup obligation unknown | observed, required, owner-decision | Ratify periods, backup/restore objectives, and budget behavior |
| Clean install | Mutable checkout and home-local paths | observed, required | Produce a clean, verified, useful host-role result |
| User-local deployment shape | Current implementation shape | observed, retire | Retire after a supported install reproduces the ratified portrait |
| Classic runtime | Deployed authority | observed, retire | Retire only after independent equivalence, explicit switch, archive, and rehearsed rollback |

No row decides that SMART, the Docker adapter, databases, logs, ZFS, GPU, or
the self-probe should be kept or removed.

## Application overlays

Application testimony remains owned by the application and is admitted by NQ
through an identified profile/provider boundary. Generic host checks remain
separate perspectives.

### Candidate Labelwatch overlay

The overlay should be able to testify, within a ratified exact profile, about:

- main-loop, discovery, and API process identity and configured enablement;
- ingest, scan, derive, report, and publication phase progression;
- last successful phase times, duration, backlog, and bounded staleness;
- primary database and WAL state plus application-owned transaction/progress
  markers where available;
- discovery and event coverage with explicit denominators;
- read-health and signal-health semantic verdicts;
- report or API publication freshness and consumer usability;
- Driftwatch facts-bridge presence, age, coverage, and missing-data effect; and
- limitations and cannot-testify boundaries.

The census does not ratify exact fields, thresholds, phase transitions,
denominators, or baseline ownership. Those are owner decisions bound into the
private static cohort if they change verdict meaning.

### Candidate Driftwatch overlay

The overlay should be able to testify about:

- exact build and configured emit mode;
- stream consumer cursor and progression;
- lag, event rate, baseline coverage, reconnect and drop behavior;
- queue depth and recheck progression;
- sensor-array, retention, maintenance, facts-export, and other required
  feature enablement;
- preflight and bake/gate semantic verdicts;
- primary DB, WAL, disk pressure, emergency brake, retention, and growth;
- facts snapshot identity, freshness, completeness, and Labelwatch-consumer
  usability; and
- limitations and cannot-testify boundaries.

Simple `/health`, Docker `healthy`, systemd up, Prometheus samples, and
`/health/extended` are distinct evidence surfaces. Current code returning HTTP
200 with a failing JSON verdict must not be flattened into green.

### Other deployed applications

The Linode's governor, web UI, bridge, receipts feed, PostgreSQL, Caddy, PDS,
and NQ services have generic lifecycle testimony. Whether any requires a
dedicated overlay is an owner decision. Sushi-k's
`governor-code-adapter` likewise requires an explicit retain/repair/overlay or
retire decision.

## Shared failure domains and contradiction obligations

The portrait must make these relationships visible:

- Labelwatch and Driftwatch share the Linode host, clock, local networking,
  proxy path, and parts of their storage dependency chain.
- Driftwatch data and Labelwatch zonestorage depend on `/dev/sdc`; two
  application observations using that storage are not automatically
  independent.
- Caddy fronts several sites; proxy reachability and application progression
  are different claims.
- Local NQ self-probing shares the host, process environment, and network
  namespace with the service it observes.
- systemd/Docker state, application-native progress, database/WAL state, log
  activity, Prometheus projection, and remote reachability may contradict one
  another without one erasing another.
- Logical `labelwatch-host` identity must not drift to static hostname
  `localhost`.

The stable NQ diagnostic export must preserve the relation state as agreement,
contradiction, shared failure domain, unknown independence, or not compared.
Nightshift may compose those typed results over time; Maude or another
frontend may render them. Neither consumer may flatten the relation into an
unsupported condition.

## NQ and Nightshift self-diagnosis obligations

For each subject, the portrait should expose:

1. exact NQ core build, static cohort, profile catalog, evaluator, detector
   suite, protocol, and store identities;
2. Nightshift recurrence/campaign state: last requested diagnostic, last
   admitted completion, next expected run, expiry, lateness, overlap, and
   refusal;
3. expected versus actual provider, helper, profile, subject, scope, and
   vantage inventory;
4. helper absence, permission denial, admission drift, byte drift, malformed
   output, timeout, stale result, and unsupported substrate as distinct states;
5. store schema/open result, WAL, disk use, retention pass, budget/runway,
   latest verified backup, and write refusal;
6. typed NQ diagnostic read/export and inspector availability plus Nightshift
   operational-output compatibility;
7. alert-intent and delivery-receipt coverage without folding it into
   host condition; and
8. active NQ findings and missing evidence even when the observation loop
   itself is current.

The sushi-k state `liveness: ok` plus five critical findings is the forcing
example: Nightshift recurrence success cannot render an all-clear.

## Operator task acceptance

| Task | Candidate acceptance result |
|---|---|
| Coverage and currency | Identify every required domain as current, partial, stale, refused, missing, unsupported, intentionally excluded, or not configured |
| Host pressure and capacity | Inspect CPU/load/pressure, memory/swap/pressure, filesystem bytes/inodes/read-only state, and device/mount relationships |
| Service lifecycle | See exact ratified inventory, current state, recent changes, and whether inventory closure is established |
| Network and reachability | Separate interface, route, listener, proxy, DNS, TLS, local probe, and external vantage |
| Storage and databases | See exact database/WAL targets, configured-but-unobserved paths, growth/pressure, and limits of file testimony |
| Application progression | Distinguish liveness from Labelwatch and Driftwatch phase, cursor, lag, queue, coverage, publication, export, and gate state |
| Self-diagnosis | Determine NQ build/cohort, provider/helper, admission, store, and typed export plus Nightshift recurrence/expiry/campaign/posture and alert-delivery state |
| Operational composition | Let Nightshift own recurrence, expiry, campaigns, and multi-diagnostic posture while keeping each NQ subject, question, disposition/refusal, and limitation intact |
| Presentation | Let the Nightshift enterprise surface expose profiles, last-result time/applicability/coverage/expiry, and current posture; let Maude or another frontend render typed NQ and Nightshift output without reconstructing authority |
| Notification delivery | Determine the exact diagnostic/operational state transition, Nightshift/operator alert intent, attempt, transport outcome, and receipt only under later-ratified meanings |
| Backup and retention | See periods, runway/budget enforcement, latest verified backup, restore qualification, and legacy archive boundary |
| Triage | See supported condition, contradictions, limitations, shared failure domains, and useful safe next checks without action authority |

## Typed diagnostic read/export and operational presentation obligations

The candidate successor requirement is not an NQ-owned dashboard. NQ must
provide a stable, typed, machine-facing read/export contract that:

- keeps coverage, condition, and operator work state separate;
- shows the exact subject, source/provider, scope, vantage, evidence time, and
  freshness behind a disposition;
- preserves current, partial, stale, refused, missing, unsupported,
  intentionally excluded, and not configured;
- preserves condition present, explicitly absent, and unknown;
- carries exact disposition or refusal identity and enough bounded detail for
  a consumer to avoid false no-action or all-clear presentation;
- supports separately scoped profile results for host pressure, service
  lifecycle and changes, filesystem/storage/WAL, network, logs, application
  progression, contradictions, and shared failure domains;
- exposes NQ self-diagnosis and retention/backup state;
- provides useful safe next checks without granting authority to act;
- supports first-line consumers without requiring private-table SQL; and
- remains read-only with respect to collection and operational remediation.

`nq-monitor`, if retained as a successor name or tool, is limited to inspecting
one diagnostic's evidence, custody, admissibility, coverage, evaluation,
disposition, or refusal. It is not the whole-estate monitoring console.

Nightshift must preserve the exact NQ inputs it composes, apply identified
recurrence and expiry rules, identify campaigns and operational
policy/context, and emit a stable current-posture result without rewriting an
NQ disposition or refusal. Its enterprise console contract must show the
configured diagnostic profiles and each profile's last result, result time,
current applicability, coverage, expiry state, and contribution to current
posture. Maude or another frontend must consume the typed NQ and Nightshift
contracts, expose alert intent and delivery-receipt coverage, and present
urgent facts honestly. Presentation is not the source of diagnostic truth,
operational authority, or delivery custody.

The observed Classic NQ Monitor remains a live historical/product fact and an
equivalence input. It does not make an NQ-owned dashboard a successor
requirement. This draft does not choose Maude, another web application, a
terminal UI, transport, port, authentication mechanism, or deployment
topology.

## Candidate notification delivery seam

`nq-notify` is a candidate boundary name only.

The existing NQ-NG notification outbox and attempt tables are unratified
scaffolding. Their location and field names do not select the notification
carrier, alert-intent law, delivery contract, or component owner.

Candidate obligations are:

- consume an exact alert intent emitted by Nightshift or explicit
  operator policy for an identified diagnostic or operational state
  transition, with every NQ disposition or refusal identity that informed it;
- preserve diagnostic-output, state-transition, alert-intent, and policy
  identity through an attempt;
- retain inspectable receipts or explicit failed, refused, or unknown attempt
  outcomes; and
- remain unable to create alert intent, change the NQ diagnostic
  output, or grant action authority.

Not selected or ratified:

- repository, crate, binary, daemon, package, queue, library, or in-process
  implementation shape;
- schema;
- delivery law;
- which diagnostic or operational state transitions produce alert intent;
- transports and recipients;
- routing, suppression, retry, replay, deduplication, ordering, escalation, or
  retention semantics; and
- the meanings of attempt, acceptance, delivery, refusal, and unknown.

A configured Slack, Discord, or future transport does not prove delivery. A
transport receipt does not prove human attention. Notification failure does
not rewrite the underlying NQ condition. A raw NQ finding, evaluation,
disposition, or refusal does not automatically page.

## Retention, backup, and historical boundary

Observed on both subjects:

- 2,880-generation retention at a 60-second cadence, approximately 48 hours;
- prune cadence every 60 cycles; and
- configured DB budget fields.

Observed differences:

- sushi-k declares 200 MB, explicitly unenforced in deployed source;
- labelwatch-host declares 100 MB, has a main NQ DB larger than that value, and
  did not establish enforcement; and
- neither census established a complete backup, restore, or archive
  obligation.

Candidate obligations:

1. the operator ratifies separate retention for evidence, evaluations,
   findings/dispositions, refusals, application overlays, and notification
   receipts;
2. budgets are either enforced under an exact contract or shown as unenforced
   with current size and runway;
3. main DB, WAL, checkpoint, backup, and restore state remain distinct;
4. backups are identified and semantic reopening is verified;
5. package removal does not silently destroy state;
6. Classic history is frozen under an explicit access policy and is not
   imported as current NQ-NG state; and
7. split observation intervals during trial or rollback remain explicit.

Exact periods, backup destination, frequency, recovery objectives, and
acceptable data loss remain owner decisions.

## Clean installation and lifecycle qualification

A clean-install qualification should start from an empty supported host and
use only the candidate artifact and literal documentation. It should establish:

- exact artifact identity and checksum;
- no sibling checkout, developer `target/`, remote compiler, or unrecorded
  source dependency;
- explicit role and target inventory before collection;
- config and compatibility validation before state creation;
- provider/helper qualification and admission or an explicit refusal;
- first useful host and application result;
- visible omitted, missing, unavailable, stale, and refused coverage;
- explicit enable/start state;
- restart and Nightshift recurrence continuity;
- backup and verified restore;
- upgrade and rollback behavior;
- notification delivery coverage or explicit no-delivery standing; and
- no Classic mutation or authority switch merely because the trial succeeds.

These are result obligations. This draft does not choose Debian, tar, a
configuration manager, a container, one command, multiple packages, or any
other installation shape.

## Candidate functional-equivalence meaning

If ratified, functional equivalence would require:

1. every ratified required row to produce same-target evidence with equal or
   stronger bounded semantics;
2. every inventory closure and exclusion to be explicit;
3. coverage and condition taxonomy to survive acquisition, storage,
   evaluation, typed diagnostic export, Nightshift recurrence/current-posture
   composition, frontend presentation, backup, and alert-delivery projection;
4. application overlays to preserve their application-owned semantics rather
   than substituting generic liveness;
5. NQ self-diagnosis and typed diagnostic export, Nightshift recurrence,
   expiry, campaigns and current posture, frontend consumption, alert delivery
   coverage, retention, backup, clean install, upgrade, and rollback to pass
   literal operator tasks;
6. Classic and NQ-NG to run in isolation for an operator-selected evidence
   window;
7. contradictions and semantic differences to be recorded rather than forced
   into equality;
8. no Classic finding to be imported as current NQ-NG state;
9. each retire candidate to receive an explicit operator disposition; and
10. an explicit authority switch with rehearsed rollback and frozen Classic
    archive.

This candidate does not select the comparison window, acceptable deviations,
cutover date, or rollback window.

## Owner decisions required before ratification

The operator must approve, reject, or refine:

- the complete per-subject inventory of services, containers, processes,
  filesystems, mounts, devices, interfaces, routes, listeners, endpoints,
  logs, databases, WALs, metrics, and external dependencies;
- every explicit exclusion;
- CPU, memory, filesystem, storage, WAL, log, network, and application
  thresholds and baseline owners;
- Labelwatch and Driftwatch phase maps, fields, denominators, freshness,
  consumer contracts, and semantic detector suite;
- whether governor, receipts-feed, Caddy, PDS, PostgreSQL, and other deployed
  services need dedicated overlays;
- sushi-k `governor-code-adapter`, SMART, ZFS, GPU, SQLite, WAL, logs, and
  local/external probe dispositions;
- external-vantage requirements and permitted shared failure domains;
- notification policy, recipients, transports, outcome meanings, retries, and
  receipt retention;
- evidence, disposition, refusal, overlay, receipt, and Classic archive
  retention;
- backup and restore objectives;
- supported clean-install platforms and surface;
- typed NQ diagnostic export/single-diagnostic inspection, Nightshift
  profile/last-result/applicability/coverage/expiry/current-posture output,
  frontend acceptance tasks, and required access boundaries;
- parallel-run, equivalence, authority-switch, and rollback windows; and
- every row marked retire.

Until those decisions are recorded by an operator, this portrait remains
`candidate_for_operator_ratification` with authority `none`.

## No action or mutation

These artifacts were derived from the named read-only census records. Drafting
them did not inspect new credentials or application payloads, contact a host,
run a collector, open a database writable, build or test code, edit Rust,
change a service or container, deploy, commit, push, or switch authority.

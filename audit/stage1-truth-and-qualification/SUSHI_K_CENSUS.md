# sushi-k deployed NQ Classic census

Audit date: 2026-07-27

Scope: the live local `sushi-k` deployment, its local NQ Classic checkout, and
checked-in supporting deployment material.

Method: read-only inspection without using prior assistant memory, deployment
memory, credentials, or unrelated host data.

## Claim classes

This record keeps four claim classes separate:

- **Observed** — read directly from the live local process, filesystem,
  loopback endpoint, or SQLite database during this audit.
- **Source-verified** — read from the exact deployed Classic commit where
  available, or from current checked-in source when explicitly identified as
  current rather than deployed behavior.
- **Inferred** — a bounded conclusion from observed and source-verified facts.
- **Unknown** — not established by this local audit and not filled in from
  repository prose or historical deployment records.

Repository prose is not live deployment evidence. Current checkout state is
not deployed state merely because the deployed binaries came from the same
repository.

## Result

`sushi-k` runs an active NQ Classic deployment, but it is a user-local
developer deployment rather than a reproducible production install. It
observes basic host state, six explicitly named services, and one local
blackbox probe of NQ itself. It does not currently observe application
databases, SQLite WAL targets, logs, ZFS, GPU state, DNS, TLS, or an external
application endpoint.

One configured collector is broken by path drift. The only Docker target is
down. The live database consequently exposes five active critical findings.
Notification policy has no delivery channel.

NQ-NG is not yet a functional replacement for this already-limited portrait:
its current host profile covers hostname, uptime, CPU count, and one-minute
load only.

## Observed deployment identity

### Active user services

| Unit | State at audit | Start time | Executed artifact |
|---|---|---|---|
| `nq-publish.service` | loaded, enabled, active/running | 2026-07-27 10:50:30 EDT | `/home/jbeck/git/nq-root/nq/target/release/nq-witness` |
| `nq-serve.service` | loaded, enabled, active/running | 2026-07-27 10:50:24 EDT | `/home/jbeck/git/nq-root/nq/target/release/nq-monitor` |
| `nq-blackbox.service` | loaded, enabled, active/running | 2026-07-21 12:10:06 EDT | `/home/jbeck/nq/blackbox/blackbox_exporter` |

The unit files are:

- `/home/jbeck/.config/systemd/user/nq-publish.service`
- `/home/jbeck/.config/systemd/user/nq-serve.service`
- `/home/jbeck/.config/systemd/user/nq-blackbox.service`

They point into a mutable developer checkout and home-local state rather than
the `/usr/local`, `/etc/nq`, `/var/lib/nq`, and system-service layout described
by current Classic production documentation.

### Files and build identity

| Purpose | Observed path | Observed mode or identity |
|---|---|---|
| Publisher config | `/home/jbeck/nq/publisher.json` | `0664`, `jbeck:jbeck` |
| Aggregator config | `/home/jbeck/nq/aggregator.json` | `0664`, `jbeck:jbeck` |
| Evidence database | `/home/jbeck/nq/nq.db` | about 63.3 MiB at audit |
| Live WAL | `/home/jbeck/nq/nq.db-wal` | about 6.5 MiB at audit |
| Liveness record | `/home/jbeck/nq/liveness.json` | generated each monitor cycle |

The liveness record identified deployed build commit `361c5cdfa491`, schema
64, contract version 1. The local Classic checkout was
`2e956d27616bcb7e49016b4d7867c9455c4129a7`, twenty commits ahead of its
configured upstream. These identities are not interchangeable.

The deployed binary's help surface did not contain the current documentation's
`config validate`, `database compatibility`, or `--version` commands. This is
observed deployed/current-doc drift, not evidence that current source lacks
those commands.

## Observed configuration

### Monitor

| Field | Observed value |
|---|---|
| Bind | `127.0.0.1:9848` |
| Source | `sushi-k` at `http://127.0.0.1:9847` |
| Source timeout | 10 seconds |
| Collection interval | 60 seconds |
| Database | `/home/jbeck/nq/nq.db` |
| Retention | 2,880 generations |
| Prune cadence | every 60 cycles |
| Disk budget fields | 200 MiB, warn at 80% |
| Liveness file | `/home/jbeck/nq/liveness.json` |
| Notification eligibility | warning and above |
| Notification channels | zero |

At a 60-second interval, 2,880 generations is approximately 48 hours and a
60-cycle prune cadence is approximately one hour. The disk-budget fields are
declarative only in both deployed commit `361c5cdfa491` and current source; no
runtime enforcement may be inferred from their presence.

### Publisher targets

| Target class | Observed declarations |
|---|---|
| systemd | `gnome-remote-desktop`, `cron`, `smartmontools`, `ttyd`, `rsyslog` |
| Docker | `governor-code-adapter` |
| Prometheus | `nq_aggregator_http_localhost` |
| SQLite metadata | none |
| SQLite WAL | none |
| Logs | none |
| ZFS | not configured |
| SMART | configured, 15-second timeout, `sudo -n` wrapper |
| GPU | not configured |

The Prometheus target is a local `http_2xx` blackbox probe from
`127.0.0.1:9115` to the NQ monitor at `127.0.0.1:9848`. It is not an external
vantage and does not observe Labelwatch, Driftwatch, or another application.

The configured SMART helper path was:

```text
/home/jbeck/git/nq-witness/examples/nq-smart-witness
```

That path did not exist. The helper was present at:

```text
/home/jbeck/git/nq-root/nq-witness/examples/nq-smart-witness
```

This exact path drift explains the live collector error.

## Observed collector results

Classic invokes every collector family and represents absent configuration as
empty or skipped output. Invocation alone does not establish coverage.

| Collector | Live status | Live payload | Bounded interpretation |
|---|---|---|---|
| Host | `ok` | one host snapshot | Basic host testimony is current |
| Services | `ok` | six rows | Only the six declared targets are observed |
| SQLite health | `ok` | zero rows | No application database coverage |
| Prometheus | `ok` | 17 samples | One local NQ self-probe |
| Logs | `skipped` | none | No log coverage |
| ZFS | `skipped` | none | Not configured; no ZFS conclusion |
| SMART | `error` | none | Configured testimony unavailable |
| GPU | `skipped` | none | Not configured; no GPU conclusion |
| SQLite WAL | `ok` | zero rows | No WAL target coverage |
| NQ binary | `ok` | one binary observation | Publisher binary observation is current |

The blackbox sample set included `probe_success=1` and HTTP status 200 for the
local NQ monitor. NQ Classic stores these samples but does not automatically
turn `probe_success` into an application-health claim or alert.

## Observed current service and finding state

Five systemd targets were up. `governor-code-adapter` was down.

The read-only `v_warnings` surface contained five active critical rows:

| Kind | Count | Subject or cause |
|---|---:|---|
| `check_failed` | 2 | long-lived warnings and services-not-up saved checks |
| `node_unobservable` | 1 | `smart.local.sushi-k` |
| `service_status` | 1 | `governor-code-adapter` down |
| `smart_witness_silent` | 1 | SMART testimony unavailable for about 46 days |

The liveness file simultaneously reported `status: ok`, generation `135666`,
and `findings_observed: 5`. Therefore its `ok` is evidence that the monitor
loop completed; it is not an all-clear system-health verdict.

Observed declaration counts were:

- zero coverage rules;
- zero operational-intent declarations;
- eight maintenance declarations; and
- one configured source.

No complete intended-service, intended-storage, or application-coverage
manifest was observable.

## Source-verified deployed thresholds

The live aggregator config does not override detector or escalation
thresholds. The following defaults were verified from deployed commit
`361c5cdfa491`; current source retains the same values:

| Detector family | Threshold |
|---|---|
| WAL bloat | 5% of DB size; 256 MiB absolute floor below a 5 GiB DB |
| Freelist bloat | 20%; 1 GiB absolute floor |
| Staleness | two generations |
| Pinned WAL | 256 MiB plus six hours without main-DB incorporation |
| Info to warning | 30 consecutive generations |
| Warning to critical | 180 consecutive generations |
| Host disk pressure | above 90%; above 95% is immediate-risk classification |
| Host memory pressure | above 85% |
| SMART witness silence | five minutes |
| NVMe wear | 80% used |
| NVMe available spare | 10% remaining |
| NVMe temperature | 70°C |
| SCSI temperature | 55°C |
| ATA temperature | 50°C |

At the observed cadence, the default escalation generations correspond to
approximately 30 minutes and three hours. Threshold presence does not create
coverage where no target is configured.

## Capability comparison

| Capability | Observed Classic on sushi-k | Current NQ-NG source | Successor requirement |
|---|---|---|---|
| Host identity, uptime, load | Present | Present | Preserve with parallel comparison |
| Memory pressure | Present | Absent | New compiled profile/helper/detector |
| Root capacity | Present | Absent | Exact filesystem profile |
| Mount and inode inventory | Absent | Absent | Declare need, then implement |
| systemd and Docker state | Six declared targets | Absent | Service-manager profile |
| Application HTTP semantics | Absent | Absent | Application-specific JSON profiles |
| SQLite application metadata/WAL | No live target | Absent | Declare actual DB obligations |
| Logs | No live target | Absent | Declare source/window semantics |
| Prometheus/blackbox | One local self-probe | Absent | Reachability/DNS/TLS profiles as required |
| SMART | Broken | Absent | Packaged, privilege-bounded helper/profile |
| ZFS/GPU | Unconfigured | Absent | Conditional on declared host role |
| Notifications | Zero channels | No delivery worker | Explicit delivery policy and qualification |
| Retention automation | Approximately 48 hours | Absent | Explicit durable policy |
| Operator read surface | Loopback web/API/SQL | CLI/Unix API; console opt-in | Qualify against real operator tasks |
| Evidence/refusal custody | Classic lifecycle | Strong typed NQ-NG custody | NQ-NG advantage, not breadth parity |

Current NQ-NG's native host profile testifies only to hostname, uptime, CPU
count, and one-minute load and has one load-pressure detector. NQ-NG's own
implementation status explicitly says the sushi-k portrait, Classic collector
parity, notifications, retention, and network profiles are not complete.

## Inferred findings

The following are inferences, not directly observed configuration fields:

1. This is a developer-operated proving deployment, not a productized install.
   The evidence is its user services, mutable checkout binaries, home-local
   configs/state, and hand-installed blackbox exporter.
2. A fresh operator cannot reconstruct intended sushi-k coverage from the
   checked-in repositories. The live configuration is outside the repository,
   and no coverage or operational-intent declaration closes the inventory.
3. NQ-NG would currently regress operational breadth if it replaced Classic,
   even though its custody and refusal model is stronger.
4. A successful `http_2xx` probe of NQ itself provides no evidence that
   application ingestion, semantic health, public reachability, DNS, or TLS is
   working.
5. The current critical findings are monitoring facts requiring an operator
   decision; this audit does not authorize repair, retirement, restart, or
   paging.

## Unknowns

The audit did not establish:

- whether the six service targets are the intended complete inventory;
- whether `governor-code-adapter` should still exist or be running;
- whether SMART is required and should be repaired, or should be explicitly
  retired;
- which mounts, databases, WALs, logs, endpoints, DNS names, and TLS
  properties are intended coverage;
- whether any off-host monitoring observes sushi-k;
- which notification receiver or delivery guarantee is required;
- the required history, backup, and restore period;
- whether any workflow consumes Classic finding history or saved checks beyond
  the configured generation-retention horizon; or
- the acceptable parallel-qualification and rollback window for a successor.

These remain unknown rather than being inferred from repository examples.

## Qualification consequences

- Classic remains the live authority until a successor independently observes
  the declared host/application portrait and an explicit switch is authorized.
- Fixing the stale SMART path or changing the down service was outside this
  census and requires a separate operator action.
- A successor trial should use isolated state and service identity, preserve
  Classic, and compare the same declared targets over a bounded interval.
- Missing target declarations must produce visible unknown/refused coverage,
  not green absence.
- Notification delivery must be inventoried and qualified independently from
  finding/disposition evaluation. The candidate `nq-notify` facet is recorded
  in `FRESH_OPERATOR_AUDIT.md`; no repository, package, process, or transport
  shape is ratified here.

## Evidence and no-mutation record

Read-only command classes used:

- filesystem discovery, content reads, metadata and modes;
- Git status, identity, ancestry, and exact-commit source reads;
- `systemctl --user show`;
- loopback HTTP GETs;
- `sqlite3 -readonly`; and
- binary help/argument parsing.

No file, config, database, service, package, repository history, remote, or
credential was changed during the census. No service was started, stopped,
restarted, enabled, disabled, or reloaded. No build, test, commit, push, or
deployment was performed.

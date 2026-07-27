# Stage 1 Linode Census

## Status

Read-only production census of `labelwatch.neutral.zone`.

Observed on 2026-07-27 from approximately 16:30 through 16:46 UTC. This
record describes the deployed host as observed. It is not an installation
receipt, a health verdict, or proof that configured coverage is complete.

No endpoint was invoked, no database was opened writable, and no remote
state was intentionally changed.

## Scope and safety boundary

The census was authorized to inspect:

- host OS and toolchain identity;
- Classic NQ binaries, schema, services, configuration identities, and
  aggregate operational state;
- configured collector, target, retention, threshold-category, and
  notification-transport surfaces;
- Labelwatch and Driftwatch service topology;
- scoped storage and listener dependencies;
- installed help and documentation discoverability.

The census did not inspect:

- webhook values, tokens, passwords, credentials, or other secret values;
- shell history, Claude memory, unrelated user content, or application
  payloads;
- raw log examples or finding messages;
- Labelwatch DIDs or configured external endpoint values;
- the contents of the remote dirty NQ source rewrite as product authority.

Slack and Discord notification transports are configured and historic
notification rows exist. This census does **not** establish delivery
reliability, retry behavior, semantic adequacy, or authorization guarantees
for either transport.

## SSH identity and isolation

The observed server host key was:

```text
ED25519 SHA256:pBe1nMF/Y1lM37p0oaDNaHZ6Bg/qltdPibqwqquzDmc
```

SSH used the authorized identity
`/home/jbeck/git/claude/ssh/linode`, `IdentitiesOnly=yes`, and an isolated
known-hosts file:

```text
/tmp/nq-stage1-linode-known-hosts
```

No user or system `known_hosts` file was modified. The first connection
attempt accepted the host key into that temporary file but was rejected with
`Too many authentication failures`; the successful retry added
`IdentitiesOnly=yes` and used the same pinned temporary host-key record.

## Verified deployment identity

### Host

| Field | Observed value |
|---|---|
| Platform | Linode KVM compute instance |
| Operating system | Ubuntu 22.04.5 LTS (Jammy) |
| Kernel | Linux 5.15.0-171-generic x86-64 |
| systemd | 249 |
| Static hostname | `localhost` |
| NQ logical source/instance | `labelwatch-host` |
| Git | 2.34.1 |
| Python | 3.10.12 |
| SQLite CLI | 3.37.2 |
| Docker client/server | 28.1.1 |
| jq | 1.6 |
| curl | 7.81.0 |
| Rust/Cargo | not installed |

The system hostname and NQ logical host identity are different. The NQ
identity is explicitly configured; it is not derived from the host's
`localhost` name.

### Classic NQ

| Surface | Observed value |
|---|---|
| Publisher binary | `/opt/notquery/nq-witness` |
| Monitor binary | `/opt/notquery/nq-monitor` |
| Publisher config | `/opt/notquery/publisher.json` |
| Monitor config | `/opt/notquery/aggregator.json` |
| State database | `/opt/notquery/nq.db` |
| Liveness artifact | `/opt/notquery/liveness.json` |
| Publisher listener | `127.0.0.1:9847` |
| Monitor listener | `0.0.0.0:9848` |
| Database schema | 64 |
| Aggregation interval | 60 seconds |
| Declared source | one: `labelwatch-host` |
| Source timeout | 10 seconds |
| Retention | 2,880 generations |
| Prune cadence | every 60 cycles |
| Configured DB budget | 100 MB |
| DB warning point | 80% |
| Notification threshold | `warning` |
| Notification transports | Slack and Discord, endpoint values redacted |

Both NQ services were active and running as the systemd default user, root.

The installed NQ binaries do not expose `--version`; each rejects it as an
unexpected argument. `nq-monitor --help` is discoverable and lists its serve,
query, inquiry, finding, liveness, fleet, maintenance, source, preflight,
witness/receipt, smoke, probe, and drill surfaces. `nq-witness --help`
documents its required configuration path.

No installed NQ Debian package was found. Rust and Cargo are absent, so this
host does not contain a reproducible build toolchain for the deployed
binaries.

### Deployed-binary/source separation

The remote source checkout at `/opt/notquery/src` reported:

```text
HEAD 2077dd2e1e2ec2a9ef53ee9d4e961c03d4a9a8bf
tree 6e87a7d3c30993c0f5b9100c3b8ba445ca264e0e
```

It also contained extensive tracked modifications and deletions. It was
therefore excluded as authority for the running product.

The deployed binaries match the rollback artifacts named
`.pre-2e956d2` byte-for-byte:

| Artifact | SHA-256 |
|---|---|
| deployed `nq-witness` | `20663dd7d9c114ddaa3c6721ad3bde06c98ff3e31572397340d41bec5b617c2b` |
| `nq-witness.pre-2e956d2` | `20663dd7d9c114ddaa3c6721ad3bde06c98ff3e31572397340d41bec5b617c2b` |
| rejected/rolled-back `nq-witness.2e956d2` | `9ba962aaf986944d81e59ebacba9e9c88d26a29072dd4c706e2992b84013f89e` |
| deployed `nq-monitor` | `e1136b5c4fac4d34b28b4433c967186d95c90ef72741c9d14c15c51aa61ed559` |
| `nq-monitor.pre-2e956d2` | `e1136b5c4fac4d34b28b4433c967186d95c90ef72741c9d14c15c51aa61ed559` |
| rejected/rolled-back `nq-monitor.2e956d2` | `dc436a97d48d2761cc89cba21fa9547eddb8dde82db2bc2d006c5334b5d7281d` |

That proves which rollback artifacts are running. Association of those
artifacts with Classic commit `361c5cd` is inferred from deployment naming
and prior campaign history; the installed binaries do not embed a
discoverable source revision, so this census does not promote that
association to a verified fact.

## Host Operational Portrait capability matrix

The latest immutable database snapshot used for the collector census was
generation 183895, completed at `2026-07-27T16:41:31.301839707Z`.

| Portrait area | Collector/result | What is established | Important limitation |
|---|---|---|---|
| Observation loop | source `labelwatch-host`: OK | one source returned within the 60-second loop | no independent expected-source inventory |
| Host identity/state | `host`: OK, 1 entity | load, memory availability/pressure, root-disk capacity, uptime, kernel, boot identity | no CPU utilization, PSI, swap, OOM, per-mount, inode, or block-I/O state |
| Required services | `services`: OK, 14 entities | state/PID for the configured service set | configured-set coverage, not service discovery |
| SQLite metadata | `sqlite_health`: OK, 3 entities | size/page/freelist/journal metadata for three observed DBs | four paths are configured; the missing fourth path is not made explicit by the result |
| WAL state | `sqlite_wal_probe`: OK, 3 entities | WAL state for Labelwatch, NQ, and Driftwatch labeler DBs | no application transaction or query correctness |
| Logs | `logs`: OK, 4 entities | bounded journald count/classification for four configured units | no durable raw custody or complete absence claim |
| Prometheus | `prometheus`: OK, 1,675 entities | samples from node and external-HTTP target families | Prometheus projection is not provenance-complete evidence |
| NQ self-observation | `nq_binary`: OK, 1 entity | installed NQ binary observation | does not attest source/build correspondence |
| ZFS | `zfs_witness`: skipped | collector absence is explicit | no ZFS portrait |
| SMART | `smart_witness`: skipped | collector absence is explicit | no device-health portrait |
| GPU | `gpu_witness`: skipped | collector absence is explicit | no GPU portrait |
| Coverage contracts | zero `coverage_rules` rows | no declared coverage rules were found | empty rules cannot establish completeness |
| Detector execution | conditional across generations | generations 183896 and 183897 each ran one detector and observed one finding | a single generation may report zero detector executions |
| Network portrait | not represented in NQ state | none | no interface, route, listener, DNS-path, or dependency inventory |

### Point-in-time host values

At generation 183895, Classic recorded:

| Field | Value |
|---|---|
| Load 1m / 5m | 0.71 / 0.86 |
| Memory total / available | 7,937 MB / 6,444 MB |
| Derived memory pressure | 18.81% |
| Root disk total / available | 160,683 MB / 34,450 MB |
| Root disk used | 78.56% |
| Uptime | 12,500,691 seconds |
| Kernel | 5.15.0-171-generic |

These are observations, not a health declaration.

The main NQ database file was 134,979,584 bytes, excluding its WAL and
backups, while the configured DB budget is 100 MB. This is a measured
configuration/state discrepancy, not a diagnosis of its cause.

## Declared services and data substrates

### Service subjects

The configured service set was:

- systemd:
  - `labelwatch`
  - `labelwatch-api`
  - `labelwatch-discovery`
  - `labelwatch-lock-watcher`
  - `governor`
  - `gov-webui`
  - `governor-bridge`
  - `receipts-feed`
  - `postgresql@15-main`
  - `postgresql@17-main`
  - `nq-publish`
- Docker:
  - `driftwatch`
  - `caddy`
  - `pds`

All 14 were reported `up` in the captured generation. NQ monitoring this
exact configured list does not establish that no undeclared service exists
or that every operationally required service is represented.

### SQLite paths

Four general SQLite paths are configured:

```text
/opt/driftwatch/deploy/data/labeler.sqlite
/opt/driftwatch/deploy/data/facts.sqlite
/opt/driftwatch/deploy/data/facts_work.sqlite
/opt/receipts-feed/data/receipts.sqlite
```

Only three rows were present in `monitored_dbs_current`:

| Path | Observed main size | Observed WAL size |
|---|---:|---:|
| Driftwatch `facts.sqlite` | 3,092.05 MB | not reported |
| Driftwatch `labeler.sqlite` | 2,543.64 MB | 10.61 MB |
| receipts-feed `receipts.sqlite` | 225.25 MB | not reported |

`facts_work.sqlite` is configured but was not present in the captured
current-state rows. This census does not infer why.

Explicit WAL targets are:

```text
/var/lib/labelwatch/labelwatch.db
/opt/notquery/nq.db
/opt/driftwatch/deploy/data/labeler.sqlite
```

### Logs and Prometheus

Configured journald sources:

```text
labelwatch
nq-serve
governor
nq-publish
```

Configured Prometheus target names:

```text
node
external_http_nq_neutralzone
```

Target URL values were deliberately not recorded. The installed
blackbox_exporter is version 0.28.0. This census confirms an external-HTTP
probe family exists; it does not establish an independent foreign-network
vantage or failure-domain independence.

### Detector and notification categories

Detector categories observed historically in the schema-64 database:

```text
check_failed
error_shift
log_silence
resource_drift
service_status
signal_dropout
wal_bloat
```

The stored observations examined did not carry explicit numeric
degradation/recovery thresholds. Exact compiled detector thresholds remain
unknown from the installed operator surface.

Historic notification rows prove that Classic recorded attempted or
completed notification activity for categories including service state,
staleness, disk pressure, WAL/freelist bloat, source errors, check failure,
and service flap. They do not establish a durable delivery queue, retry
contract, recipient correctness, or delivery semantics.

## Labelwatch topology

### Verified runtime

| Surface | Observed value |
|---|---|
| Package | `labelwatch` 0.1.0 |
| Install root | `/opt/labelwatch` |
| Python environment | `/opt/labelwatch/.venv` |
| Main config | `/opt/labelwatch/config.toml` |
| Main service | user/group `labelwatch`; ingest every 120 seconds; scan every 300 seconds; report every 3,600 seconds |
| API | `labelwatch-api.service`, loopback `127.0.0.1:8423` |
| Discovery | `labelwatch-discovery.service`, Jetstream discovery with a six-second backstop interval |
| Incident aid | root-run `labelwatch-lock-watcher.service` |
| Primary DB | `/var/lib/labelwatch/labelwatch.db` |

The redacted configuration key classes establish dependencies on:

- database path;
- service URL;
- configured labeler set;
- discovery enablement and cadence;
- Driftwatch facts path;
- boundary derivation enablement and cadence.

Values for service URL and labeler identity were not recorded.

### Operator surface

Installed `labelwatch --help` is functional and exposes commands including:

- ingestion, scan, report, and export;
- discovery and census;
- climate, account-label lookup, and provenance;
- coverage delta and index audit;
- hosting-locus comparison/diff;
- authority-effect review workflow;
- scope presentation and bounded state pilot;
- assessment and publication;
- long-running `run` and API `serve`.

Read-only help was also confirmed for `report`, `coverage-delta`,
`index-audit`, `hosting-locus`, and `assess`.

No `signal-health` command appears in the installed top-level help. This
does not prove no equivalent internal behavior exists; it means that exact
operator command is not discoverable from the installed CLI surveyed.

### NQ ownership boundary

Classic NQ monitors Labelwatch through generic:

- systemd state;
- SQLite/WAL state;
- journal summaries;
- Prometheus samples.

It does not expose Labelwatch's application-native climate, coverage,
hosting-locus, provenance, or consumer-query semantics as a dedicated NQ
profile. Those semantics are donors for an independent Labelwatch provider
or profile, not proof that Classic already owns them.

## Driftwatch topology

| Field | Observed value |
|---|---|
| Container | `driftwatch` |
| Container state | running, Docker health `healthy` |
| Container ID | `be94f4a628bac445c96fe093600c2d756e840e93e4dd8dddd0473237a8aa645b` |
| Image ID | `sha256:a53b222deb3d146d828068fca47e944166dfa91245142b65335108a698b04021` |
| Image repository digest | none |
| Embedded short revision | `GIT_SHA=70109c8` |
| Entrypoint process | `uvicorn`, running as root |
| Container root filesystem | writable |
| Restart policy | `unless-stopped` |
| Network | `deploy_default` |
| Published port | container 8000 to host loopback `127.0.0.1:8422` |
| Data bind | `/opt/driftwatch/deploy/data` to `/app/data`, read-write |
| Output bind | `/opt/driftwatch/deploy/out` to `/app/out`, read-write |

Environment variable **names**, but not values, show operational families
for:

- event/edge/claim retention;
- retention interval and batching;
- claim and longitudinal recheck;
- firehose/Jetstream input;
- facts export;
- fingerprint normalization;
- label emission.

Classic NQ monitors Driftwatch container state and selected SQLite/WAL
substrates. It does not establish consumer-visible export reachability,
artifact identity, schema correctness, freshness, or queryability.

## Scoped storage and network dependencies

| Path | Backing filesystem |
|---|---|
| `/opt/notquery` | root `/dev/sda`, ext4 |
| `/opt/labelwatch` | root `/dev/sda`, ext4 |
| `/var/lib/labelwatch` | root `/dev/sda`, ext4 |
| `/opt/driftwatch/deploy/out` | root `/dev/sda`, ext4 |
| `/opt/driftwatch/deploy/data` | `/mnt/zonestorage` on `/dev/sdc`, ext4 |
| `/mnt/zonestorage/labelwatch` | `/mnt/zonestorage` on `/dev/sdc`, ext4 |

Relevant listeners:

| Component | Listener |
|---|---|
| NQ publisher | `127.0.0.1:9847` |
| NQ monitor | `0.0.0.0:9848` |
| Labelwatch API | `127.0.0.1:8423` |
| Driftwatch | `127.0.0.1:8422` to container port 8000 |

A shared Caddy container/service fronts NQ, Labelwatch, Driftwatch, and other
sites. Its complete routing configuration was outside the narrow census.

## Port-versus-donor classification

This is a planning classification, not an implementation authorization.

### Behaviors to reproduce natively in NQ-NG

- explicit host/source identity and observation freshness;
- host load, memory, root-capacity, boot, kernel, and self-observation;
- explicitly declared service state for systemd and Docker;
- SQLite metadata and WAL observation;
- bounded log-source observation with honest `quiet`, error, and missing
  distinctions;
- qualified Prometheus and blackbox intake;
- detector history and notification outbox semantics;
- explicit unsupported/skipped coverage.

These should become NQ-NG providers/profiles and conformance behavior, not a
merge of Classic runtime, database, pack, or dashboard code.

### Classic donor requirements, not authority

- the exact deployed service/DB/log/Prometheus target census;
- historic detector categories and operational thresholds after independent
  recovery;
- retention and state-volume behavior;
- operator notification categories;
- the observed rollback and deployment-friction lessons.

### Independent application ownership

Labelwatch and Driftwatch should export their own consumer-visible
application evidence through independent providers/profiles. NQ should
admit and compose that evidence without absorbing either application's
private monitor logic into the base NQ product.

Prometheus/blackbox output is a qualified, potentially lossy acquisition
path. It is not a substitute for NQ custody, projection checks, coverage, or
consumer-owned reliance.

## Verified, inferred, and unknown

### Verified

- the host key, OS/tool versions, services, listeners, mounts, binary/config
  hashes, schema version, collector outcomes, declared targets, and
  application topology recorded above;
- Classic's generic host/service/SQLite/WAL/log/Prometheus breadth;
- the exact rollback-artifact byte identity of the deployed NQ binaries;
- Slack and Discord transport configuration, with values redacted;
- historic notification records;
- an empty `coverage_rules` table;
- conditional detector execution across successive generations;
- absence of Rust/Cargo and absence of an installed NQ Debian package.

### Inferred

- deployed-binary association with Classic commit `361c5cd`, based on
  rollback naming and prior campaign evidence;
- that `/dev/sdc` loss would affect both Driftwatch data and Labelwatch
  zonestorage, based on scoped mount resolution;
- that some configured-but-unobserved SQLite state represents a coverage
  gap. The reason for absence is not inferred.

### Unknown or explicitly not established

- cryptographically exact source revision for each deployed Classic binary;
- full compiled numeric detector thresholds;
- an independent inventory of all required services, mounts, interfaces,
  listeners, and external dependencies;
- true blackbox-vantage independence;
- complete closed-world absence semantics;
- Slack/Discord delivery, retry, recipient, authorization, and semantic
  guarantees;
- application-native Labelwatch and Driftwatch success/progression state;
- whether the configured 100 MB DB budget is enforceable or why the file
  exceeded it;
- whether any omitted subject was intentionally unsupported, accidentally
  unconfigured, or currently absent.

## Command ledger

All remote commands were metadata reads, help invocations, or immutable
database reads.

Connection shape:

```text
ssh -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o UserKnownHostsFile=/tmp/nq-stage1-linode-known-hosts \
    -o StrictHostKeyChecking=yes \
    -i /home/jbeck/git/claude/ssh/linode \
    root@labelwatch.neutral.zone <read-only-command>
```

Command classes used:

- `ssh-keygen -lf` on the isolated temporary known-hosts file;
- `sed` on `/etc/os-release`, `uname`, `hostnamectl`;
- tool `--version` discovery;
- `systemctl list-unit-files`, `list-units`, `list-timers`, `show`, and
  filtered `cat`;
- `dpkg-query` for relevant installed packages;
- `stat`, `sha256sum`, and `file`;
- NQ and Labelwatch `--help`;
- Labelwatch `pip show`;
- `jq` field-path discovery and allowlisted configuration summaries;
- `sqlite3 file:/opt/notquery/nq.db?immutable=1` for schema and aggregate
  monitoring-state queries;
- selected `docker ps`, `inspect`, `image inspect`, `port`, and `top`
  metadata;
- environment-variable **name** extraction only;
- scoped `findmnt`;
- PID-specific `ss`;
- Git `rev-parse`, `show`, and `status --untracked-files=no` without
  inspecting untracked contents.

No `curl`, HTTP request, NQ smoke/probe/inquiry, Labelwatch collection,
Docker exec, package operation, service-control operation, cleanup, deploy,
or database-write command ran.

Python help and metadata commands set:

```text
PYTHONDONTWRITEBYTECODE=1
PYTHONNOUSERSITE=1
HOME=/nonexistent
XDG_CACHE_HOME=/nonexistent
```

## No-mutation evidence

Initial and final SHA-256 values matched:

| Static artifact | Initial and final SHA-256 |
|---|---|
| `/opt/notquery/nq-witness` | `20663dd7d9c114ddaa3c6721ad3bde06c98ff3e31572397340d41bec5b617c2b` |
| `/opt/notquery/nq-monitor` | `e1136b5c4fac4d34b28b4433c967186d95c90ef72741c9d14c15c51aa61ed559` |
| `/opt/notquery/publisher.json` | `ed263a946f87fdfb1e9e4029543b0d2a9fc0180af1669cca09b39caf2a24b6c3` |
| `/opt/notquery/aggregator.json` | `881b588c5f8f51c90e42285cf344e5aebb16cf4fb24a3efeeaa3421ed8d9b51f` |
| `/opt/notquery/blackbox/blackbox.yml` | `1835ce98ed4d027fdb3327b5027845dfbfc3e1fbd21880a5da4c6b3e5a1fec1f` |
| `nq-publish.service` | `3f034e2762404a2181d828479ff3f82141bb91e74302be79c0dc4c3553094d7c` |
| `nq-serve.service` | `7770b7eefe9a013084b083f06620bf5c3408c769da100d6af8267360b70da1fa` |
| `nq-blackbox.service` | `50932bc2acd6a305c7cabcd30ea82302d9d1bab669cd4c2dd61ed8f641ea1b7e` |
| `labelwatch.service` | `40c8f987c78871a392afc7ecd106d6ff98f67901391002ce7f80ef1aa996f7fd` |
| `labelwatch-api.service` | `f9e0dc489e4223fb95b1aa3ea05088fd1f726ba1525f0408b47ee83fe6085ef6` |
| `labelwatch-discovery.service` | `45edf291a365683a8a2aa0930ef08fd2e440767765232faa6e4a104436b095b5` |
| `labelwatch-lock-watcher.service` | `ca079a241a9fcb223f4ffa78c4b7189badcebdca3046b499c7bc310b3a587050` |
| `/opt/labelwatch/config.toml` | `acc91f5ea49ee4204252afedf65c9a6893dc409e8aab7372847e38c9afce2bde` |
| `/opt/labelwatch/pyproject.toml` | `14f57f7613a97ba8c5134d7f2c749b2660e7f3253ee620d3591cfbdd95208b12` |
| `/opt/labelwatch/.venv/bin/labelwatch` | `2b33dc9d01bb2887e97914c8437db4d1e154a49135f41d04013ab256ac4ff1d8` |

Relevant service process identities and start timestamps were unchanged:

| Unit | PID | Start time |
|---|---:|---|
| `nq-publish.service` | 3836376 | 2026-07-27 14:52:26 UTC |
| `nq-serve.service` | 3836377 | 2026-07-27 14:52:26 UTC |
| `nq-blackbox.service` | 2782221 | 2026-07-03 16:39:44 UTC |
| `labelwatch.service` | 1802574 | 2026-06-14 00:04:25 UTC |
| `labelwatch-api.service` | 1802573 | 2026-06-14 00:04:25 UTC |
| `labelwatch-discovery.service` | 1802572 | 2026-06-14 00:04:25 UTC |
| `labelwatch-lock-watcher.service` | 1454356 | 2026-04-14 16:59:06 UTC |

The Driftwatch container ID, image ID, healthy state, and start timestamp
also remained unchanged:

```text
container be94f4a628bac445c96fe093600c2d756e840e93e4dd8dddd0473237a8aa645b
image     sha256:a53b222deb3d146d828068fca47e944166dfa91245142b65335108a698b04021
started   2026-07-27T16:16:32.308220286Z
```

The live NQ database was intentionally excluded from byte-identity
comparison because its already-running 60-second loop continued to append
state during the census. Every census query used SQLite `immutable=1`, so
the census itself did not create or modify DB/WAL/SHM state.

No file was edited, no service or container was restarted, and no package,
deployment, cleanup, or collection action was performed on the remote host.

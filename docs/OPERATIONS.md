# NQ operations: current scope and historical runbook

The current source has SQLite schema v13, including retained saved-check,
maintenance-declaration, and notification-delivery custody. The small supported
starting path is the credential-free local saved-check example in
[`SAVED_CHECKS.md`](SAVED_CHECKS.md). Notification delivery is documented in
[`NOTIFICATIONS.md`](NOTIFICATIONS.md): local deterministic transport and the
Nightshift replay boundary have been exercised. Live destination delivery has
been verified with a person confirming receipt: Slack on 2026-10-01 (disposable
VM and the Linode host), Discord on 2026-10-02 (qualification host, released 0.2.0 binary),
and PagerDuty on 2026-10-02 (non-production service: trigger, dedup, resolve).
The records are in Cartography `audit/2026-10-01-observation-profile-vm-result.md`,
`audit/2026-10-01-linode-observation-profile-live.md` and
`audit/2026-10-02-notification-sinks-live.md`.
A recurring Monitor/NQ/Nightshift profile has not been exercised. The
PagerDuty Events API v2 route, its routing-key provisioning and its
trigger/resolve/resubmit procedure are in
[`PAGERDUTY_RUNBOOK.md`](PAGERDUTY_RUNBOOK.md); no NQ or Constellation
component emits PagerDuty conditions yet
([`PAGERDUTY_ALERT_MAP.md`](PAGERDUTY_ALERT_MAP.md)). `nq status export`
derives the `notification`/`outbox` component from retained delivery records
at read time, so its output changes for any store that has delivery records,
Slack-only stores included. A PagerDuty record left `unknown` (for example
after a timeout) blocks rollover for the life of the store.

The remainder of this runbook preserves the earlier NQ-ng developer-preview
service procedures. It remains useful for its named daemon, package and
diagnostic surfaces, but its schema-v5 and “not implemented yet” statements are
historical. Do not treat those statements as a description of saved checks or
notification delivery, and do not infer that every historical service procedure
has been requalified for schema v12.

## Historical developer-preview runbook

Package installation creates a service identity and empty standard directories
only. It never creates or replaces configuration, initializes a database,
admits a helper, migrates data, enables the service, or starts it.

The walkthrough below uses the one-shot `stdio` conformance specimen; the same
protocol exchange is also supported by a supervised persistent `unix` helper
carrier with private sockets and peer-credential checks. The preview includes
compiled profiles, admission locks, explicit collection, a resident scheduler,
SQLite schema v5, verified SQLite backup/restore, exact qualified
v3-to-v4-to-v5 migration, immutable diagnostic-artifact custody and
export/import, read-only exports, the Unix API, and an opt-in loopback console.
Broader historical migration chains, notifications, retention automation,
privileged hardware helpers, and package-driven upgrades are not implemented
yet.

Two distinct local surfaces, deliberately separated:

- the **Unix socket API** (`/run/nq/nqd.sock`, mode 0660) — always enabled,
  group-bounded by filesystem permissions (DAC); and
- the **loopback HTTP console** — host-local and UID-agnostic (any local user
  can reach it), and therefore **off by default**. The packaged unit ships no
  console address, so `nqd` binds no INET listener. Opt in by adding
  `--console-address=127.0.0.1:8787` to the `nqd` invocation.

## Paths and identities

The packaged defaults are:

| Purpose | Path |
|---|---|
| Human configuration | `/etc/nq/nq.toml` |
| SQLite evidence store | `/var/lib/nq/nq.db` |
| Admission locks/history | `/var/lib/nq/admissions/` |
| Operator-created backups | `/var/lib/nq/backups/` |
| Local read API | `/run/nq/nqd.sock` |
| Private supervised-helper runtime directory | `/run/nq/helpers/` |
| Loopback console (opt-in; off by default) | `http://127.0.0.1:8787/` when enabled |

`nqd` runs as `nq:nq` and immediately execs the installed `nq daemon`, so the process that evaluates a watcher is the same `nq` executable that admitted it (admission binds the evaluator's exact bytes); packaged watchers default to the separate
`nq-helper:nq-helper` identity. Configuration may name another local account
or decimal UID, but it must resolve through the account database to an exact
non-root UID and primary GID. Admission records both. A helper may share
neither the daemon UID nor its primary GID. State and admissions are mode
`0700`; membership in the `nq` group grants access to the local API socket, not
direct database access. Only add trusted local readers to that group.

The packaged `nq-helper` account is a convenient default, not per-instance
containment. Helpers that share it also share a Unix identity and therefore a
failure and denial-of-service domain: a compromised helper can consume that
identity's resources and may interfere with peer processes permitted to the
same UID. Use distinct dedicated execution accounts when watchers have
different trust, availability, backend, or privilege boundaries; each account
is admitted independently.

Configured resource limits install per-process address-space, CPU,
file-descriptor, and regular-file-size ceilings plus Linux's per-real-UID
process/thread ceiling; core dumps are disabled. For a persistent Unix helper,
the CPU ceiling is cumulative across its lifetime. These are intentionally
recorded bounds, not a per-instance cgroup claim: processes sharing an account
also share its NPROC accounting, and many children/files can multiply
per-process/per-file ceilings. The service adds aggregate 2 GiB memory, no
swap, and 200% CPU and 256-task ceilings, plus separate 64 MiB private
filesystems for `/tmp` and `/var/tmp`. Use distinct helper accounts where that
shared failure domain is unacceptable.

## Verify and install an artifact

Verify release checksums before installing anything:

```sh
sha256sum --check SHA256SUMS
dpkg-deb --info nq-ng_VERSION_ARCH.deb
sudo dpkg -i nq-ng_VERSION_ARCH.deb
```

Debian's unrelated `nq` package also owns `/usr/bin/nq`. The NQ-ng package
declares that conflict, so `dpkg` refuses rather than overwriting it. Remove the
other package only as an explicit cutover decision; this packaging does not
provide side-by-side executable renaming.

For a tarball, verify both the outer checksum and every inner file in an
unprivileged staging directory:

```sh
sha256sum --check nq-ng-VERSION-linux-ARCH.tar.gz.sha256
mkdir nq-stage
tar -xzf nq-ng-VERSION-linux-ARCH.tar.gz -C nq-stage
cd nq-stage/nq-ng-VERSION-linux-ARCH
sha256sum --check share/nq/MANIFEST.sha256
```

The archive paths are relative to `/usr`. Review them before copying into the
host filesystem. After a manual tar installation, create only the account and
empty layout, then reload systemd:

```sh
sudo systemd-sysusers /usr/lib/sysusers.d/nq.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/nq.conf
sudo systemctl daemon-reload
```

These commands do not initialize NQ. The Debian package also deliberately
leaves `nqd` stopped and disabled.

To read which build is deployed, ask the installed binary rather than the
package name: `nq --version` prints `nq 0.2.4 (<commit>)` (and `nqd --version` prints `nqd 0.2.4 (<commit>)`),
where `<commit>` is the full git commit id release automation recorded at
compile time through `NQ_SOURCE_COMMIT`; `nq --build-info` prints the same
commit as `source_commit` in a one-line JSON document
(`nq.build_info.v2`) alongside the component, version, and helper isolation
policy, without reading any configuration. Every binary in a release carries
the same commit because the assembler refuses a cohort whose commits differ or
are absent, and the qualification package receipt binds that commit through the
recorded build environment. A development build without `NQ_SOURCE_COMMIT`
prints `nq 0.2.4` and `"source_commit":null`, and is not packageable.

At every service start under the intact packaged unit, systemd runs the
installed inner-manifest check from `/usr` before `config check`. Missing or
changed packaged bytes fail startup:

```sh
cd /usr
sha256sum --quiet --check /usr/share/nq/MANIFEST.sha256
```

This detects local package drift; it is not a signature and does not replace
verification of the outer release checksum before installation. A privileged
actor able to replace and reload the unit can remove the startup gate; verify
the unit through the package or inner manifest when that threat is in scope.
Restore drift by reinstalling the exact verified package, never by
recalculating the shipped manifest in place.

## Configure and initialize

The package installs its sample outside `/etc`. Install it only when no active
configuration exists:

```sh
sudo test ! -e /etc/nq/nq.toml
sudo install -o root -g nq -m 0640 \
  /usr/share/doc/nq-ng/examples/nq.toml /etc/nq/nq.toml
sudo -u nq nq --config /etc/nq/nq.toml config check
```

Review and replace the sample nonce before admission. The sample's helper path
is `/usr/lib/nq/helpers/nq_conformance_helper.py`; a source-tree execution must
use a candidate configuration with the helper's absolute source path instead.
One daemon accepts at most 32 watcher instances. Each admitted launch chain is
also bounded to 32 byte artifacts, 32 MiB per artifact, and 64 MiB in total;
live sealed launch snapshots share a 512 MiB process ceiling. `config check`,
admission, and daemon drift verification fail closed when the relevant boundary
is exceeded.

Initialization is explicit and fails rather than taking ownership of an
existing incompatible database:

```sh
sudo -u nq nq --config /etc/nq/nq.toml init
```

With the sample watcher configured, `doctor` is expected to report a missing
admission until the next section is complete. That is a useful failed state,
not a reason to create a lock by hand.

At the time this historical section was written, the binary normally opened
only SQLite schema v5. The current source opens schema v13 and has an explicit
upgrade from the published v5 schema. For a v5 store, the v5→v12
transition takes a separate verified backup and adds empty saved-check custody;
it also adds empty notification-delivery custody, without synthesizing historical
checks or delivery records. Development schema versions6–11 are not accepted
inputs to this public migration. The subsequent v12→v13 transition takes its
own verified backup and adds empty local-successor acquisition custody. Use the current binary's `admin
upgrade` output and preserve every recorded backup before relying on an older
schema procedure below.

The historical v3/v4 discussion records the then-supported migration sources:
schema v4, and the exact schema-v3 artifact shipped in the qualified `v0.1.0`
release. `admin upgrade` validates the complete source schema and stored
semantics, creates and reopens a digest-addressed backup for each transition,
and applies v3-to-v4 and then v4-to-v5 transactionally.
Historical v3 watcher runs retain explicit `provider_intake_not_recorded`
gaps; the migration manufactures neither provider identities, raw captures,
durable acknowledgments, nor diagnostic artifacts that the source never
stored. Any historical v3 checkpoint bytes remain preserved for reopening,
but cannot advance the live cursor because no exact provider-intake
acknowledgment exists for them.

Schema v1, schema v2, stale or modified v3/v4 databases, and every other
incompatible representation remain fail-closed and byte-preserved. `init`,
normal open, backup/restore, and daemon startup refuse them without rewriting
their meaning. Preserve incompatible bytes with a cold archive; such an archive
records `source_openable=false` and makes no semantic-reopen claim.

At a hard successor cut, provide the already-created immutable legacy manifest
digest; this records a reference and imports no legacy finding state:

```sh
sudo -u nq nq --config /etc/nq/nq.toml init \
  --legacy-manifest-digest sha256:LOWERCASE_64_HEX_DIGEST
```

## Test and admit a watcher

Test performs a bounded dry exchange but creates no admission state. Admit
runs the same bounded exchange, records admission history, and commits an
authoritative binding event plus a recoverable active-lock materialization:

The `nq` account deliberately has no capabilities in an ordinary login shell,
so a direct `sudo -u nq nq watcher test/admit/rotate` cannot enter the separate
watcher identity. Define this maintenance helper in the operator's current
shell. `systemd-run` passes the argv directly—there is no shell evaluation—and
runs `nq` as `nq:nq` with the same four-capability ceiling as `nqd`:

```sh
nq_helper_command() {
  sudo systemd-run --quiet --wait --pipe --collect \
    --property=User=nq \
    --property=Group=nq \
    --property=UMask=0077 \
    --property=NoNewPrivileges=yes \
    --property=PrivateTmp=yes \
    --property='TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M /var/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M' \
    --property=ProtectSystem=strict \
    --property=ProtectHome=yes \
    --property=ProtectClock=yes \
    --property=ProtectControlGroups=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelTunables=yes \
    --property=ProtectHostname=yes \
    --property=RestrictNamespaces=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes \
    --property=RemoveIPC=yes \
    --property=KeyringMode=private \
    --property=SystemCallArchitectures=native \
    --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
    --property=ReadOnlyPaths=/etc/nq \
    --property='ReadWritePaths=/var/lib/nq /run/nq' \
    --property='CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' \
    --property='AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' \
    --property=LimitNOFILE=4096 \
    --property=LimitFSIZE=1G \
    --property=LimitCORE=0 \
    --property=TasksMax=256 \
    --property=MemoryMax=2G \
    --property=MemorySwapMax=0 \
    --property=CPUQuota=200% \
    -- /usr/bin/nq "$@"
}
```

`CAP_SETUID` and `CAP_SETGID` enter the admitted account and clear groups;
`CAP_CHOWN` transfers exact Unix-socket custody; `CAP_KILL` terminates and
reaps a distinct-UID helper. The child clears every capability and enables
`no_new_privs` before helper exec. The transient unit also mirrors the daemon's
filesystem, home, temporary-directory, namespace, kernel, and address-family
restrictions; keep it synchronized with `nqd.service`. Use it for commands that
execute or runtime-verify a watcher: `watcher test/admit/rotate/rollback`,
`collect`, and `doctor`. In particular, `doctor` and rollback trace the current
runtime loader under the admitted watcher UID, so they are not capability-free
inspection operations. Configuration, initialization, backup, restore,
upgrade, query, status, findings, and other pure exports remain capability-free
`sudo -u nq nq ...` operations.

```sh
sudo -u nq nq protocol check
nq_helper_command --config /etc/nq/nq.toml \
  watcher test conformance-local
nq_helper_command --config /etc/nq/nq.toml \
  watcher admit conformance-local
nq_helper_command --config /etc/nq/nq.toml doctor
```

Admission identifies bytes and binds the compiled profile; it does not grant
authority. Never hand-edit an admission JSON document.

Collection, test, admission, rotation, rollback, revocation, and freshness
evaluation take one cross-process lock per instance. A daemon collection and
an operator mutation therefore cannot overlap, while unrelated instances stay
independent. The lock directory is derived from the canonical database
path/device/inode and refuses a symlinked lock directory, so a second process
cannot evade serialization by using a database symlink alias or a drifting
admissions directory.

The append-only database binding event is authoritative. Its filesystem
materialization intent commits in the same transaction; completion is appended
only after the active lock/history and containing directory are durable. If a
process dies in that window, the next lock holder replays the pending intent.
The intent binds the canonical admissions-root path/device/inode/mode; recovery
refuses to write into a newly configured or replaced directory.
NQ never uses this recovery path to hide ordinary lock tampering: without a
pending intent, a missing or different active file is reported as drift.

Checkpoint-enabled helpers resume only inside the exact cursor namespace that
produced the checkpoint: admission/binding, profile digest, subject, scope,
vantage, and granted capabilities. V1 profiles cannot declare a cursor portable
across implementations, so every admission rotation deliberately starts with
no inherited checkpoint.

For each later launch, NQ opens and compares the configured executable chain,
then starts the helper from the retained opened files. Replacing a pathname
cannot redirect the qualified launch, and changing the retained bytes in place
causes refusal before spawn. The same rule applies to one-shot stdio helpers
and to persistent Unix-helper restarts. Executable/interpreter snapshots have
read/execute-only `0555` mode and fixed data snapshots have read-only `0444`
mode, so an isolated UID can use the sealed copies without broadening access to
the original source files. The retained working-directory descriptor closes on
exec; packaged helpers use the read-only `/usr/lib/nq/helpers` directory, never
NQ's state directory. This protects the admitted byte chain; it does not turn a
digest into a qualification or replace the separate profile, protocol,
capability, and conformance checks.

For native ELF startup, NQ first parses the exact retained executable, the
known glibc loader, and the complete bounded `DT_NEEDED` graph without running
the loader. Bare sonames resolve only through a fixed architecture-specific
system-directory order. Every object is byte-identified before NQ invokes the
loader's bounded `--list` operation with the cache and glibc hardware-capability
directories disabled; the loader's real-object set must then equal the
prequalified closure exactly. The closure and all identities are repeated
before spawn. V1 supports only host-machine ELF64 little-endian glibc layouts
on AMD64/ARM64 and system libraries under `/lib`, `/lib64`, `/usr/lib`, or
`/usr/lib64`; unresolved objects, custom loaders/roots, RPATH/RUNPATH, audit or
filter tags anywhere in the closure, and any `/etc/ld.so.preload` are refused.
Runtime artifacts, their path ancestry, and the configured working directory
ancestry must be root-owned, not writable by group/other, and have no POSIX
access/default ACL. Admission also refuses loader-redirection environment
keys. A package deployment should therefore
keep `/usr/lib/nq/helpers` and all parents root-owned `0755` (or stricter) and
must not place a helper working directory under `/tmp`, a service-owned state
directory, or another writable tree.

The runtime list is a startup guarantee only. NQ v1 does not identity-bind
later `dlopen`, Python/native-extension imports, NSS/PAM modules, GPU plugins,
or similar module systems. `$ORIGIN` and custom RPATH/RUNPATH layouts are not
supported. Only helpers that avoid later code/module loading are supportable;
the packaged Rust host helper follows that constraint. The Python specimen is
for protocol conformance and cross-language testing only, not a supported
production helper or SDK.

After executable, configuration, or profile drift, keep the daemon stopped and
use `watcher rotate`. It archives the previous active lock under the admissions
history:

```sh
sudo systemctl stop nqd.service
nq_helper_command --config /etc/nq/nq.toml \
  watcher rotate conformance-local
nq_helper_command --config /etc/nq/nq.toml doctor
sudo systemctl start nqd.service
```

The package also ships `examples/nq-host.toml`, which uses the native
`nq-host-helper` and the compiled `nq.host/v1` profile. Merge its watcher table
into the active configuration (or use it as the initial alternative), then run
the same test/admit workflow. Its capability ceiling is explicit; the helper
cannot expand it at runtime.

Rollback requires an exact retained lock path and re-verifies it against the
current bytes, configuration, protocol, and compiled profile:

```sh
nq_helper_command --config /etc/nq/nq.toml watcher rollback \
  conformance-local \
  /var/lib/nq/admissions/history/conformance-local/ADMISSION_ID/conformance-local.json
```

`watcher revoke INSTANCE` retains the admission under durable history and the
derived history path, then removes the active materialization. It is safe to
run while `nqd` is active: the per-instance transition waits for an already
bound collection to finish, prevents a new one from starting, and the daemon
quiesces its persistent helper when it observes the binding change.

## Start and inspect the service

Enable the service only after every configured instance passes `doctor`:

```sh
nq_helper_command --config /etc/nq/nq.toml doctor
sudo systemctl enable --now nqd.service
systemctl status nqd.service
journalctl -u nqd.service
```

The console and API are read-only and never trigger collection. CLI exports
read the same durable model:

```sh
sudo -u nq nq --config /etc/nq/nq.toml status export
sudo -u nq nq --config /etc/nq/nq.toml evaluations export --limit 1000
sudo -u nq nq --config /etc/nq/nq.toml findings export --format jsonl
sudo -u nq nq --config /etc/nq/nq.toml refusals export --limit 100
sudo -u nq nq --config /etc/nq/nq.toml query \
  'select * from public_finding_snapshot_v3' --limit 100
curl --unix-socket /run/nq/nqd.sock http://localhost/v3/status
curl --unix-socket /run/nq/nqd.sock \
  'http://localhost/v1/evaluations?limit=1000'
curl --unix-socket /run/nq/nqd.sock 'http://localhost/v3/findings?limit=100'
curl --unix-socket /run/nq/nqd.sock \
  'http://localhost/v1/rejected-custody?limit=100'
```

The SQL command accepts exactly a bounded `SELECT *` from
`public_finding_snapshot_v3` or `public_status_snapshot_v1`. It is an
inspection surface, never detector semantics. Finding and rejected-custody API
pages use stable `after` cursors; repeat the request with the last returned
`finding_id` or `submission_id`. Evaluation history uses a store-wide monotone
`evaluation_sequence`: retain the first page's inclusive `through_sequence`,
then pass its `next_after_sequence` as exclusive `after` with that same
`through` value. This freezes one finite logical snapshot while later
evaluations append beyond it. `nq evaluations export` accepts the equivalent
`--after` and `--through` options. Limits are 1–1000 and malformed, repeated,
escaped, out-of-range, or unfrozen cursors fail closed. `/v1/status` remains a
compatibility surface and returns an explicit upgrade response when typed
results cannot be represented. `/v2/status` returns 409 with `/v3/status` as
the required endpoint whenever governed evaluation history exists.
`/v2/findings` likewise returns an explicit response requiring `/v3/findings`;
none of these routes flatten the current carrier.

Reports are ordered by a sequence allocated when SQLite commits them. Detector
recency therefore does not depend on observation clocks or digest sorting.
For an admitted collection, sequence allocation happens inside the same
immediate transaction that writes raw custody, the report, its exact detector
evaluation/refusal/finding set, and the canonical V2 run-linked status. No
reader can observe a report without its result chain; historical stores with a
missing result, a partial/extra evaluation set, detector-suite omission or
duplication, or an evaluator artifact that differs from the admission fail
semantic reopening. Matching carrier and row edits cannot bypass those
admission-bound identities.
Evaluations receive a database-assigned revision for each detector version and
a gap-free store-wide `evaluation_sequence`; the store independently orders
each finding's internal event history. Failed transactions do not create
durable revisions or append-sequence values. Every persisted evaluation is an
`EvaluationEnvelopeV2` binding its optional triggering run, responsible
instance, subject, full scope and vantage, detector and evaluator identities,
profile identity, times, watermark, and inner `EvaluationResultV1`. Evidence
is accepted only from the exact committed report occurrence in the evaluation
snapshot, including its report identity and semantic digest. Public snapshots
expose the NQ-owned identity, digest, and relevant times. Consumers must not
reconstruct finding identities or infer evidence order from clocks or hashes.

A first-ever `CannotEvaluate` intentionally creates no finding: missing
testimony cannot manufacture a condition or a green absence. It still appears
as an authoritative evaluation component in `nq.status_snapshot.v3` and as an
immutable record in `nq.evaluation_history.v1`. A later refused evaluation for
an existing condition may retain that finding with refused visibility, but the
finding is not the source from which the evaluation is reconstructed.

## Execute, qualify, inspect, export, and import a diagnostic artifact

The bounded diagnostic command runs the configured instance, commits its
ordinary run/evaluation history and `nq.diagnostic_execution.v2` artifact in
one transaction, reopens the committed artifact, and writes the exact
canonical bytes with no trailing newline:

```sh
sudo -u nq nq --config /etc/nq/nq.toml diagnostics execute host-local \
  > diagnostic.json
```

The current producer is intentionally narrow: the existing
`nq.host.load_pressure/v1` diagnostic may emit a determinate result, a
governed received-input or detector refusal, or a typed no-byte provider
no-response/acquisition failure. An admission refusal creates no execution
artifact. Other profiles and historical runs do not receive reconstructed
artifacts. The frozen v1 contract remains a supported compatibility boundary,
not the current live-emission format.

After process restart, use the contract-owned artifact ID from the document:

```sh
sudo -u nq nq --config /etc/nq/nq.toml --json \
  diagnostics qualify sha256:LOWERCASE_64_HEX_DIGEST
sudo -u nq nq --config /etc/nq/nq.toml --json \
  diagnostics inspect sha256:LOWERCASE_64_HEX_DIGEST
sudo -u nq nq --config /etc/nq/nq.toml \
  diagnostics export sha256:LOWERCASE_64_HEX_DIGEST > exported.json
```

`qualify` is the narrow NQ-NG → Nightshift admission-provenance boundary. It
reopens the store's semantic history beyond the validation watermark (all of
it when the watermark certifies none; see
[Store validation](#store-validation-and-the-validation-watermark)),
re-proves the qualified artifact's own closure, and emits one
`nq.diagnostic_admission_provenance.v1` only for a locally produced v2
artifact. The carrier binds exact canonical bytes, the store-genesis source,
run/evaluation origin, provider intake, raw-byte and admission-context
identities, profile semantic identity, and the admitted judgment when one
exists. Governed refusal and acquisition-failure artifacts remain eligible
evidence with their distinct dispositions. Imported custody, v1 compatibility
artifacts, unavailable/corrupt bytes, and inconsistent history refuse.

Qualification is historical evidence admission only. It does not establish
freshness, present reliance, authorization, or action. Its content hash is not
a source signature; consumers must acquire it from their configured NQ-NG
source and bind the separately configured store-genesis identity.

`inspect` reports commitment, origin, schema support, exact byte state, and
the decoded diagnostic when supported. `export` returns only verified
canonical bytes; committed-unavailable and corrupt states fail explicitly.
The query index locates an artifact but never redefines its identity.

Import is a bounded custody operation over one physical regular file:

```sh
sudo -u nq nq --config /etc/nq/nq.toml --json \
  diagnostics import exported.json
```

The import receipt records committed, existing, or rematerialized custody.
Import does not authenticate the producer, qualify a profile, establish
reliance, make the artifact current, or grant authorization. Supported v1 and
v2 documents receive strict semantic and self-identity validation. Canonical
unknown schemas may be retained only as explicitly unsupported custody and
cannot enter diagnostic evaluation. Locally emitted artifacts are additionally
checked against their retained semantic history before qualification,
inspection, or export;
that local correspondence is not inferred for imported bytes.

## Replay Nightshift attention before notification delivery

An operator-asserted notification remains available without Nightshift. A
route that accepts `nightshift_receipt` intents must additionally configure
`nightshift_attention_replay` with the absolute canonical Nightshift executable,
its exact `sha256:` digest, the absolute Nightshift store locator required by
the CLI, the one approved attention-policy digest, and the local execution
account. `nq config check` validates the closed field shapes and paths.

Before NQ writes notification custody, resolves an endpoint secret, constructs
an HTTPS client, or performs transport I/O, it runs exactly
`nightshift --store STORE attention replay --bundle-stdin`
through NQ's descriptor-bound bounded process runner. NQ requires the nested
policy and receipt to match the configured policy and delivery intent, requires
`ATTENTION_REQUIRED`, and accepts only a successful replay whose expected and
recomputed receipt digests both equal the owner receipt digest. Missing
configuration, changed executable bytes, timeout, malformed output, or any
mismatch fails closed before notification state or transport effects.
NQ sends the retained canonical bundle followed by one newline on stdin and
closes the stream. Nightshift accepts one bounded JSON value. This explicit
interface avoids converting sealed descriptors into pathnames rejected by
Nightshift's existing no-symlink file reader. Older Nightshift versions without
`--bundle-stdin` are incompatible with this adapter and refuse; there is no
fallback to unchecked pathname or synthetic replay. Failure reporting retains
only a closed outcome class and never includes helper stderr.

For a Nightshift receipt, the intent's policy digest must equal that approved
digest and its stable event and transition identities must both equal the exact
attention receipt digest. This prevents one receipt from being assigned
arbitrary deduplication or transition identities. `route_reference` selects the
configured transport route. `destination_identity` is a bounded operator label
used with the stable event for deduplication; the route does not independently
verify that label as destination provenance.

Replay proves only that canonical Nightshift recomputed the exact receipt from
the supplied policy and history. It does not prove that an upstream condition
is currently true, that source testimony is correct, or that delivery occurred.
An `operator_assertion` remains a separate explicit attention kind and is never
silently converted to a Nightshift receipt.

## Apply configuration safely

There is no daemon reload in this preview. Validate a root-owned candidate,
stop scheduling, apply it atomically, restore the intended ownership (the
atomic temporary is owned by the invoking operator), admit affected
instances, and restart:

`config apply` accepts only a regular, final-non-symlink candidate of at most
1 MiB. It retains the exact bytes it validates, refuses source mutation or
path replacement observed before activation, and renames only those retained
bytes into place. A pathname race cannot substitute a different document.

```sh
sudo nq --config /etc/nq/nq.toml config check /tmp/nq.toml.candidate
sudo nq --config /etc/nq/nq.toml config diff /tmp/nq.toml.candidate
sudo systemctl stop nqd.service
sudo nq --config /etc/nq/nq.toml config apply /tmp/nq.toml.candidate
sudo chown root:nq /etc/nq/nq.toml
sudo chmod 0640 /etc/nq/nq.toml
sudo -u nq nq --config /etc/nq/nq.toml config check
nq_helper_command --config /etc/nq/nq.toml watcher admit INSTANCE
nq_helper_command --config /etc/nq/nq.toml doctor
sudo systemctl start nqd.service
```

Repeat admission for every new or changed instance. If a step fails, keep the
daemon stopped and retain both the candidate and admission history for review.

## Store validation and the validation watermark

Every open refuses an unsupported schema version, a foreign application ID,
mismatched schema metadata, a stale schema artifact digest, a missing required
object, or a schema-fingerprint difference (which also proves that every
append-only trigger is present). These checks cost O(schema) and run on every
open, read-only or writable.

### The watermark

History validation is bounded by a *validation watermark*: the sidecar
`<database>.validation-watermark.json` (for the packaged layout,
`/var/lib/nq/nq.db.validation-watermark.json`, mode `0600`). It is written only
after a validation succeeds and records:

- the store's genesis identity, schema version, and schema artifact digest;
- the store rule set (`VALIDATION_RULES`, bound to the `nq-store` package
  version) and the engine rule set (the `nq-core` package version and a digest
  of the compiled profile catalog);
- for every append-only history table, the highest validated rowid, the number
  of rows at or below it, a SHA-256 hash chain over the complete stored
  encoding of each of those rows in rowid order (the rowid and every column
  value, payload bytes included), and the digest of the bounding row;
- when the complete semantic history is also certified, the finding-lineage
  replay state at the frontier and, for every evaluation lineage, the sequence
  and revision of its newest evaluation (the evaluation heads the status
  export resumes from);
- a commitment digest over all of the above, which every open recomputes from
  the file, so an accidentally or partly edited watermark is refused.

The commitment is store-specific and detects accidents; it is not an
authenticator. It is an unkeyed SHA-256 that anyone able to write
`/var/lib/nq` can recompute, so a coherent reseal of the database and the
watermark together passes an ordinary open, and the recorded lineage heads are
trusted as written rather than re-derived from the database on open. The
status export reopens and re-validates the evaluation each recorded head
names, but it cannot see a head that consistently names an older evaluation of
its lineage or a lineage omitted from the file; full validation recomputes the
heads and refuses such a watermark. History
that an operation consumes does not depend on it: the referenced closure is
re-proven from the stored bytes, and full validation applies every law to
every row. Pinning the commitment outside the host is tracked separately.

NQ's writers only append, so the rows above a table's bound are the rows
appended since the watermark was recorded. An ordinary open does not prove
that nothing changed at or below the bound: it reads only each bounding row.
Chains are extended only over newly validated rows, so recording a watermark
costs O(new rows).

### What each open validates

With an applicable watermark (this store's genesis, this schema, these rule
sets), an open:

1. proves that each table's bounding row is present with its recorded encoding
   (one point read per table). Removing or rewriting a bounding row (a
   truncated table tail, a rolled-back database, a watermark from a later
   state of the store) refuses the open. A row inserted, removed, or rewritten
   at or below the bound elsewhere in a table is not seen by an ordinary open;
   it is refused when an operation references it and by full validation;
2. validates only rows beyond the frontier, with the same store laws full
   validation applies (stored digests, provider-intake custody and run
   correspondence, local-successor phases, refusals, run results and
   evaluation closures, evaluation/finding linkage, evaluation sequence and
   lineage contiguity, diagnostic-artifact origins and provenance, report
   associations, status sequences, current-state pointers). Each check
   selects a row when it is new or when a new row names it, so an old run that
   gains a new evaluation, status event, or submission is re-checked.
   Configuration-scale tables (descriptors, admissions, bindings, upgrade
   receipts) are validated in full on every open.

It does not re-read covered rows that no operation references. Untouched
historical row contents are not continuously reread: a referenced row is
re-proven before use, and whole-store latent corruption is found by explicit
full validation, which should be scheduled periodically.

Every engine open (`collect`, `diagnostics execute`, `acquire-next-local`,
`replay-local-successor`, watcher actions, and the daemon's collection engine)
then reopens the provider intakes and diagnostic artifacts beyond the frontier
and the remaining semantic planes (admitted reports, watcher runs, status
events, rejected custody, evaluation and finding replay) beyond the semantic
certification, resuming the finding-lineage replay from the recorded state.
Without an applicable watermark, when the watermark was certified under other
engine rules, or when it does not certify semantic history (an earlier failure
withdrew it), it validates them in full and certifies them again. A writable
engine open then extends the watermark to the frontier it captured before
validating; the recorded lineage heads are replayed only through that same
frontier, so a writer appending concurrently cannot make them disagree, and
its rows are validated by the next open. Other writable commands never write a
watermark, and read-only opens never do.

Operations that use history re-prove what they reference, whether or not the
watermark covers it:

- `replay-local-successor`, `diagnostics qualify`, `diagnostics export`, and
  `diagnostics inspect` validate the history beyond the watermark and then the
  named artifact's own closure: its bytes, origin run, provider intake,
  evaluation, and status correspondence;
- collection re-verifies the digest of every admitted report it evaluates,
  so an edited covered report is refused rather than evaluated.

`admin validate --full` remains the one explicit whole-store operation.

### Status and findings exports

`nq status export`, `GET /v3/status`, `nq findings export`, and
`GET /v3/findings` read current state. When the watermark certifies semantic
history under the running engine's rules, the status snapshot validates only
the evaluations, watcher runs, and status events beyond the watermark frontier,
folds the new evaluations into the recorded evaluation heads (the newest
revision of each lineage wins, as in the complete walk), and reopens and
validates exactly one evaluation per lineage. The findings exports validate the
evaluation history beyond the frontier. Their cost follows the number of
lineages, the current status rows, and the history appended since the last
engine open, not the store's age. Each instance's freshness sweep opens an
engine at least once a minute and advances the watermark, so the uncovered
tail stays short while `nqd` runs.

Without such a certification (no watermark, a withdrawn certification, or one
recorded under other engine rules, as after every package upgrade until the
first engine open), the status snapshot reopens the complete history as
before, which is linear in retained evaluations. The stable-snapshot rule is
the same on both paths: status rows are read before the evaluation bound, and
the capture is retried up to eight times while status history moves. The
complete history stays available explicitly through `evaluations export`
pages and `admin validate --full`.

Measured on the reference machine with release builds, wall time of one
`status export` on synthetic stores of ten evaluation lineages certified by
full validation with 100 evaluations beyond the watermark: NQ 0.2.2 took
1.3 s at 5,000 evaluations and 13 s to 14.5 s at 50,000; this build took
0.04 s at both sizes (0.02 s with nothing beyond the watermark), with
identical output. Those stores carry no watcher runs; in production each
admitted instance status also reopened the complete evaluation history
before this change, which is why an operated NQ 0.2.1 store with 1,740
collections took 17.7 s.
On a debug-build store of 342 real collections and 683 evaluations, 0.2.2
took 3.6 s and this build 0.05 s (0.74 s with 459 history rows beyond the
watermark). The `status_snapshot_work_does_not_follow_covered_history` test
counts SQLite operations: the certified snapshot adds about 20 per covered
collection round against 640 for the complete walk, and it decodes no covered
evaluation other than each lineage's newest.

### Collection cost over uptime

`nqd` keeps one collection engine per instance for its whole uptime. Before a
collection or freshness sweep evaluates, the engine validates the evaluation
and finding history the new evaluations build on. Since 0.2.4 each engine
keeps a replay cursor: the evaluation sequence it has validated through and
the lineage state there. The cursor is seeded from the evaluation-history
replay its open performs (even when a later plane then withdraws the semantic
certification). Each evaluation then validates, inside the IMMEDIATE
transaction that commits it, only what was appended since the cursor: every
new evaluation through the same per-evaluation laws as before, and the
store-wide evaluation, refusal, and finding laws for every row beyond the
append bounds the cursor last recorded, whichever writer or commit path added
it. Every commit that advances a handle's validated frontier (admitted,
non-success, and sweep commits) now checks those laws for the rows it passes.
An engine whose open could not replay the evaluation history replays it in
full in a read snapshot, without the write lock, and then validates only the
tail under it. Open-time validation and `admin validate --full` are
unchanged. The evaluation history query reads only the refusal and
finding-event rows of each page's evaluations (grouped joins) instead of
scanning both tables per evaluation, with identical rows, and run-to-
evaluation lookups read only the evaluations appended since the handle's last
commit. There is no schema change.

Up to 0.2.3 every collection replayed the evaluation history from the
engine's open, so its cost grew with uptime: on an operated store with ten
instances it went from about 1 s an hour after start to about 400 s after nine
hours (about 6,300 evaluations), and the collections' constant reads kept the
write-ahead log from ever restarting (293 MB at stop). The replays also ran
outside any transaction, so a concurrent commit could make them report a
spurious integrity failure ("evaluation append sequence does not continue the
validated sequence", or a lineage whose "new revisions ... do not continue")
and, on an engine open, withdraw the semantic certification. Those checks now
read one snapshot.

Measured with ten long-lived host-diagnostic engines collecting in turn and a
sweeper growing the history (debug assertions, optimization level 2), one
engine's collection took 21,500, 21,700, and 21,800 SQLite operations
(0.13 s to 0.15 s, helper execution included) at 1,000, 5,000, and 20,000
evaluations; a sweep's transaction held the write lock 6 ms to 8 ms. The
0.2.3 per-collection replay took 0.5 s, 2.5 s to 2.8 s, and 10 s to 15 s at
those sizes. An engine
without a cursor spends that replay once, unlocked, and then holds the lock
about 2.5 ms. On a copy of the incident store (6,311 evaluations, release
build), the 0.2.3 per-collection replay took 17.5 s to 19.7 s; validating 30
evaluations behind the cursor took 0.05 s, and 0.003 s once current. Periodic
restarts are not needed. What a collection's own evaluation reads (for
example a profile that reads every retained report of its instance) is not
bounded by this change.

The cursor detects a history shorter than the sequence it has validated, but
not a store replaced in place with a different history of the same or greater
length: rows at or below the cursor are revalidated only by the next engine
open (as rows at or below the open frontier were before 0.2.4). After
restoring or replacing the database file, restart `nqd`.

`nqd` also stops on SIGTERM (as `systemctl stop` sends) as it does on SIGINT:
it records its stopped status and closes its store connections, so SQLite
checkpoints and removes the write-ahead log. Up to 0.2.3 SIGTERM killed the
process without closing them. A collection already running in a helper is
not interrupted: the process exits after it finishes, which can follow the
`stopped` record, and systemd's `TimeoutStopSec` (45 s in the packaged unit)
bounds the wait, after which SIGKILL rolls back any open transaction.

### Full validation

Full validation runs when no watermark exists, when it cannot be decoded, when
it was written for another schema or store rule set, on `init`, on every
`admin upgrade` result, and on demand:

```sh
sudo -u nq nq --config /etc/nq/nq.toml --json admin validate --full
```

It adds SQLite `quick_check` and `foreign_key_check`, revalidates every
history row and the complete semantic history, recomputes every table's chain
from the stored rows, and refuses if any row certified by the existing
watermark was added, removed, or rewritten since, or if the finding-lineage or
evaluation heads it recorded differ from the ones the complete replay derives
at its frontier ("certified semantic state ... disagrees"). On success it records a new
watermark and prints its commitment digest. An existing store has no
watermark until its first engine open or explicit full validation; that first
validation costs a full validation.

### Refusals and warnings

- A watermark written for another store (another genesis) refuses every open
  and is never overwritten. Confirm which database belongs at the path, move
  the watermark aside, and open again.
- A changed bounding row, or an edited watermark, refuses the open with
  "run `nq admin validate --full`". Full validation then refuses if certified
  rows are missing or changed. If the database was deliberately restored or
  rolled back, move the watermark aside first; the next open validates in
  full. A power loss can also produce this state: commits are durable at WAL
  `synchronous=NORMAL`, so the last commits before a power loss may be lost
  while a watermark that already covers them survives.
- A semantic-history failure on an engine open withdraws the semantic
  certification and prints a warning; the open proceeds because it never
  required semantic history. Qualification, export, inspection, and
  collection then validate semantic history in full until an engine open or
  full validation certifies it again; every engine open retries.
- A watermark that cannot be written (for example a full or read-only
  directory) prints a warning; the open proceeds and the next open validates
  the same history again. Temporary files carry a unique name and are removed
  on failure; files left by a killed writer are removed by the next successful
  write once they are ten minutes old.

`nq --json doctor` reports the state under `validation_watermark`: `state`
(`certified`, `core_only`, `absent`, `unreadable`, `inapplicable`),
`semantic_certified`, `validated_at`, `age_seconds`, `uncovered_history_rows`
(what the next engine open must validate), and `commitment_digest`. Alert on a
state other than `certified`, or on an age or uncovered count that keeps
growing; `uncovered_history_rows` is normally above zero between an
acquisition and the next replay, so alert on growth, not on non-zero. `init`
refuses a directory holding another store's sidecar; remove the sidecar with
the old store when re-initializing. The qualification carrier deliberately does not carry this state: its
content identity must be the same on every replay of the same artifact.

### Remaining linear costs

The following still grow with retained history; every other part of an open
is bounded by the new rows, the referenced closure, and the schema:

- The closure of an artifact the watermark already covers counts and reads
  the evaluations of its run. `evaluation_runs.trigger_run_id` is not indexed
  in schema 13, so the first such lookup in a process scans the evaluation
  table once to index evaluations by run. Reopening a covered evaluation
  likewise joins `refusals` and `finding_events` on their unindexed
  `evaluation_id`, O(refusals + finding events). This is the Monitor order:
  `acquire-next-local`, then `replay-local-successor` (which records the
  watermark), then `qualify` and `export` of an artifact that is now covered.
  Measured: about 9 SQLite virtual-machine operations per retained
  acquisition, and on the reference machine 16 ms to 27 ms for such a `qualify`
  between 500 and 5,000 retained acquisitions (roughly 0.25 s at 100,000).
  Indexing these columns needs a schema change.
- Each collection still decodes and re-checks every retained admitted report
  of its instance to select its evaluation context. That is evaluation input,
  not open validation; on the reference machine one `acquire-next-local` took
  about 0.2 s, 0.6 s, and 2.1 to 2.6 s with 500, 2,000, and 5,000 retained
  acquisitions, about 0.45 ms per retained report. At that slope an
  acquisition reaches a 60-second bound at roughly 100,000 retained
  acquisitions, about 70 to 80 days at one acquisition per minute. Before a
  store approaches that size, archive it (`nq admin archive`) and initialize a
  new store. Archive with the binary that produced the store, before any
  package upgrade: a build whose compiled profile catalog differs (any change
  to the workspace `Cargo.toml` or `Cargo.lock` moves every
  `profile_semantic_id`) refuses the old store and cannot archive it, and a
  refused writable open still checkpoints the WAL. The sealed archive is the
  provenance link between the retired generation and the new store.
- The certified status export reopens each lineage's newest evaluation,
  which joins the same unindexed `refusals.evaluation_id` and
  `finding_events.evaluation_id`: one SQL scan of those tables per lineage
  head, without decoding. A current instance status whose run the watermark
  already covers builds the evaluations-by-run index above once. The
  notification delivery summary groups retained delivery custody.
- Full validation is linear in history apart from those lookups: about 7 s,
  27 s, and 81 s at those sizes, and 3.5 s on a 208-acquisition production
  store copy.

The `hot_path_work_does_not_grow_with_covered_history` test counts every
SQLite virtual-machine operation and asserts that a read-only open plus
`qualify`, and an engine open plus `replay-local-successor`, of an artifact
beyond the watermark take exactly the same number of operations however much
history the watermark covers; any per-open scan of covered history fails it.
The counter sees SQLite virtual-machine operations only: a scan expressed as
one opcode per page (an unfiltered `COUNT(*)` over a table), Rust-side work,
and tables the fixture leaves empty are invisible to it, so the invariant is
necessary, not sufficient. Keyed lookups vary by a few operations with key
position, so the test restores each certified store between 16 trials
and compares the maxima, which are exact. The same equality held at 151 against 1,502 and at 501 against 5,002 retained
acquisitions. Wall times on the reference machine were 0.03 to 0.06 s for a
bounded `qualify` and 0.07 to 0.12 s for a bounded replay at 500 to 5,000
retained acquisitions; on the 208-acquisition production store copy,
`qualify`, `export`, and `inspect` took 0.03 s and a replay 0.10 s, against
93 s, 92 s, and 60 s for NQ 0.2.0 on the same copy.

`nqd` startup still validates the store and provider-intake history in full;
`backup`, `restore`, `admin archive`, and archive verification keep their
exhaustive validation.

## Backup

Use the CLI, not a filesystem copy of a live WAL database. The current command
uses SQLite's online backup operation, includes committed pages that still
reside in the source WAL, and opens and validates the standalone result;
stopping the daemon also gives the operator an unambiguous maintenance
boundary:

```sh
sudo systemctl stop nqd.service
sudo -u nq nq --config /etc/nq/nq.toml backup \
  /var/lib/nq/backups/nq-before-maintenance.db
sha256sum /var/lib/nq/backups/nq-before-maintenance.db
sudo systemctl start nqd.service
```

The destination must not exist. Copy a retained backup off the host together
with its reported digest and protect it like the evidence database.

## Restore

Restore validates the source and refuses to replace an existing destination.
It copies through SQLite's online backup operation rather than copying only the
source's main file, so committed source WAL state is included. Keep the
previous database and WAL sidecars quarantined until validation and service
startup both succeed:

```sh
sudo systemctl stop nqd.service
sudo install -d -o nq -g nq -m 0700 /var/lib/nq/restore-quarantine
sudo sh -c 'for p in /var/lib/nq/nq.db /var/lib/nq/nq.db-wal /var/lib/nq/nq.db-shm \
    /var/lib/nq/nq.db.validation-watermark.json; do
  if test -e "$p"; then mv -- "$p" /var/lib/nq/restore-quarantine/; fi
done'
sudo -u nq nq --config /etc/nq/nq.toml restore \
  /SAFE/BACKUP/nq.db /var/lib/nq/nq.db
nq_helper_command --config /etc/nq/nq.toml doctor
sudo systemctl start nqd.service
```

If validation fails, leave `nqd` stopped. Move the failed restored file aside
and restore the quarantined database and matching sidecars as one set.
`restore` removes a validation watermark left beside the absent destination,
so the first open of the restored database validates it in full; run
`admin validate --full` afterwards to certify its semantic history again.

## Cold archive and historical reopen

For the saved-check/maintenance/notification read path, see
[Inspect saved checks in a sealed archive](HISTORICAL_READS.md). Use a separate
external inspection configuration: the sealed configuration retains its original
database path. For the separately qualified procedure that prepares an inactive
successor while retaining explicit archive reads, see
[Operator-controlled archive rollover](ROLLOVER.md). It provides no transparent
cross-store lookup and leaves activation as a separate decision.
The separate archiver pin in that guide adds bounded whole-history validation of
saved checks, maintenance declarations and notification delivery records. Older
archives keep their original verifier and validation scope; no release pin or
archived binary is replaced.

Create a cold archive at a new destination, then verify it with the exact
preserved verifier:

```sh
sudo -u nq nq --config /etc/nq/nq.toml admin archive \
  --destination /SAFE/ARCHIVES/nq-ARCHIVE-ID
/SAFE/ARCHIVES/nq-ARCHIVE-ID/bin/nq admin archive-verify /SAFE/ARCHIVES/nq-ARCHIVE-ID
```

Creation uses a verified online backup, checkpoints the standalone copy out of
WAL mode, normalizes the preserved verifier to mode `0755`, and seals an exact
file inventory. Verification requires the archive format, schema artifact,
tool version, archived-binary digest, and executing verifier bytes to agree. It
opens `db/nq.db` through SQLite immutable mode and exhaustively reopens every
admitted judgment and materialized child row, watcher-run outcome, immutable
status event, rejected-custody refusal, and complete evaluation envelope with
any finding/refusal link. It also invokes the V3 status read model and pages
the public evaluation history through one frozen upper bound, requiring its
count to equal the exhaustive validator. Verification is read-only: repeated
checks must leave every sealed byte and path unchanged.

An archive of an incompatible database is integrity custody only. It records
`source_openable=false`, does not claim typed historical semantics, and cannot
be downgraded from a valid current store merely by resealing metadata. Archive
verification never grants current standing or authority.

## Historical binary and schema upgrade

The Debian scripts stop `nqd` before replacing binaries and do not restart it.
On a systemd host, the package transaction refuses to proceed if stopping the
unit fails or its resulting active state is not exactly `inactive`. After
installing new bytes, run:

```sh
sudo -u nq nq --config /etc/nq/nq.toml admin upgrade \
  --backup-directory /var/lib/nq/backups
nq_helper_command --config /etc/nq/nq.toml doctor
sudo systemctl start nqd.service
```

Schema v13 is current. `admin upgrade` creates and semantically verifies a
digest-addressed backup before each supported transition, and returns
`already_current` only for an exactly compatible v13 store. Current source
preserves the v3→v4→v5 chain, its explicit v5→v12 transition, and a separately
backed-up v12→v13 transition;
each preserves gaps rather than manufacturing historical provider activity,
notification delivery, or saved-check results. Every backup is complete before
the corresponding source write; failure leaves that transition's source
transactionally unchanged.

Store continuity across NQ builds is **not qualified**. A migrated store can
still be refused when it is reopened: historical diagnostic artifacts are
checked against the running build's compiled profile surface and
`profile_semantic_id`, which change whenever profile or protocol sources change
(constellation-nq#12). Until continuity is qualified, the supported procedure for
moving to a different NQ build is:

1. While the old build is still installed, settle or record in-flight work,
   run `nq backup` and verify it, and `nq diagnostics export` every artifact
   you must keep. After a migration the new build may refuse both.
2. Stop `nqd`, install the new build, and move both the old database and the
   whole `/var/lib/nq/admissions` directory aside into one quarantine
   directory. An old admission lock without a binding event in the new store
   is refused: `instance ... has an active lock but no authoritative binding
   event`.
3. `nq init`, then re-admit every watcher and start `nqd`.

Keep the old backup, the quarantined admissions, and the old package bytes
together for rollback: reinstall the old package and `nq restore` the backup.

For a second observation from the same admitted local watcher, use the
[bounded local-successor profile](LOCAL_SUCCESSOR.md). Do not initialize a
different evidence owner or repeat initial-only diagnostics to imitate
continuity. A completed acquisition replays exact recorded bytes; unresolved
acquisitions refuse without automatically invoking the helper again.

There is no arbitrary migration from modified or unknown schema artifacts.
`nqd` and the
command reject those representations before any rewrite. Validation compares
the compiled definitions of tables, indexes, triggers, and views as well as the
application and schema version, so a same-named object with changed SQL is
refused. Do not force startup, edit SQLite metadata, or relabel old rows as
provider intake, acknowledgment, or typed testimony.

Rollback means reinstalling the matching previous binaries and using `nq
restore` with the verified backup for that exact transition. Reverse migration
is not assumed; use a recorded backup rather than altering a newer store in
place.

## Uninstall versus explicit data purge

`apt remove nq-ng` stops/disables the service and removes packaged files. Its
pre-removal hook fails the transaction if systemctl fails or cannot verify the
unit is exactly `inactive`.
`apt purge nq-ng` also leaves `/etc/nq`, `/var/lib/nq`, all admissions and
backups, and the `nq` and `nq-helper` accounts intact. Package lifecycle hooks
never interpret uninstall as authorization to destroy evidence.

An explicit local purge is manual and irreversible. First remove the package,
make and verify a backup outside every path below, and confirm no other service
uses either package identity. Then run the fixed-path removal deliberately:

```sh
sudo systemctl disable --now nqd.service 2>/dev/null || true
sudo rm -rf --one-file-system /etc/nq /var/lib/nq /run/nq
sudo userdel nq-helper 2>/dev/null || true
sudo groupdel nq-helper 2>/dev/null || true
sudo userdel nq 2>/dev/null || true
sudo groupdel nq 2>/dev/null || true
```

There is intentionally no `nq purge` command in the developer preview. Keep
the off-host backup and release checksums if later custody or audit is needed.

## Build offline release artifacts

Build or obtain `nq`, `nqd`, `nq-host-helper`, `nq-host-resource-helper`,
`nq-operator-beta-helper`, and `nq-synthetic-cache-result-helper` for each
target without allowing network access. They must be `--release` builds from
one reviewed source commit, compiled with `NQ_SOURCE_COMMIT` set to that
commit's full 40-character id so each binary records it. Verify the checked-in
descriptor catalog against that exact `nq` binary and the
`nq-host-resource-helper` it will ship with, then pass those inputs to the
assembler:

```sh
mkdir -p dist
export NQ_SOURCE_COMMIT=$(git rev-parse HEAD)
cargo build --release --locked
python3 profiles/verify_catalog.py target/release/nq \
  --helper target/release/nq-host-resource-helper
SOURCE_DATE_EPOCH=0 scripts/build-release-bundle.sh \
  0.2.4 amd64 target/release profiles dist
(cd dist && sha256sum --check SHA256SUMS)
```

`dist/` is the ignored workspace artifact bank for final release outputs.
Temporary directories may hold assembler scratch or verification extractions,
but do not publish or cite `/tmp` paths as durable release custody.

The assembler invokes no network client and no compiler. It creates a
reproducible tarball, a binary Debian package, per-artifact checksums, and
`SHA256SUMS`. Produce AMD64 and ARM64 artifacts from separately built binaries;
never relabel one architecture's executable as the other.

The assembler verifies the profile catalog (including that the packaged
`nq-host-resource-helper` serves exactly the failure-code vocabularies `nq`
compiles) and architecture, then executes
each binary's configuration-independent `--build-info` probe. It requires the
requested version exactly, rejects any binary with debug assertions or the
debug same-identity exception compiled in, requires production
separate-identity policy, and requires every binary to record the same full
source commit (a `null` or malformed `source_commit`, or two binaries
reporting different commits, is refused before staging; the accepted commit is
printed as `source_commit` in the assembler's final report). It refuses
profile files outside the strict manifest,
refuses protocol assets outside the exact v1 inventory, matches the fixture
byte digest to the packaged `nq` receipt, strictly verifies the bounded
system-contract schemas and fixtures against their manifest, binds their
compiled-profile fixture to the exact profile catalog being packaged, and
verifies an exact generated payload path/type/mode/digest allowlist before
either archive is assembled. The shared recorded commit establishes that the
six binaries name one source revision; it does not establish that the revision
was reviewed, so release automation must still build from a reviewed commit.

Only one assembler may own an output-directory inode at a time. Complete
outputs are built and fsynced under a hidden same-filesystem directory, then
published with atomic renames; `SHA256SUMS` is renamed last and is the bundle
commit marker. After an abrupt kill, ignore any new public files unless that
marker exists and verifies them. A hidden `.nq-release-publish.*` directory is
uncommitted scratch, never a release; after proving no assembler is running,
it may be removed and the build rerun. Exercise both the environmental and
failure boundaries without touching `dist/`:

```sh
scripts/test_release_reproducibility.sh \
  0.2.4 amd64 target/release profiles
scripts/test_release_failure_atomicity.sh \
  0.2.4 amd64 target/release profiles
```

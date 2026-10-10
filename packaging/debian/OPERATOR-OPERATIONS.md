# NQ installed operation

The prepared combined candidate targets Ubuntu 22.04 amd64. Use its source-free
[operator guide](https://github.com/unpingable/unpingable-site/blob/dev/operator-beta/constellation/combined-candidate/README.md) for download verification, exact package installation,
separate enrollment, Workbench, currentness and day-two recovery. It is a neutral
owner-review candidate; BC1 is not tagged or published. Component source alone
does not install the composed product or grant authority.

The selected collector/store/profile owner determines configuration and startup.
Use the candidate's documented enrollment; do not run two collectors against one
store. `nqd.service` is disabled until configured and explicitly enabled. The
Workbench local exercise uses its separately enrolled `nqd-ops.service` instead.

Inspect `nq --build-info`, service status and journal, then the source-defined
`nq --help` commands for diagnosis. Successful transport or a running service
does not establish current same-boot evidence. Missing/stale/refused evidence
stays visible until collection and native admission recover.

Before replacing a helper/generation, preserve state and owner-managed rollback,
stop its writer and follow the combined day-two procedure. A replaced executable
inode may invalidate admission; a package reinstall never renews effect authority.
Removal stops the packaged collector but preserves user state. Stop any separately
enrolled collector before package removal. Purge is not a state-recovery procedure.

## Retention and capacity: component maintenance

These instructions describe the schema-v14 component. They do not activate a
collector or qualify the composed product. Stop the selected collector before
initialization, migration or restore; a separately enrolled `nqd-ops.service`
is a different unit whose actual limits must be inspected. Do not initialize
an existing store or start a second writer from this guide.

The intended ordinary-history target is seven days (`604800` seconds).
Capacity refusal never silently shortens it. Optional configuration keys use
integer bytes and seconds; omit a key to use its automatic default:

```toml
[retention]
horizon_seconds = 604800
# byte_ceiling = 8589934592
# reserve_bytes = 1073741824
# auxiliary_bytes = 67108864
```

The commented values are illustrative overrides, not recommended universal
allocations. Set overrides before `init`, or before a supported schema upgrade
establishes the first envelope. Changing the policy of an existing store is
refused; there is no general live resize command.

At initial admission NQ measures filesystem total/available bytes, free inodes,
existing store occupancy and the actual process soft per-file size limit.
Automatic reserve is the larger of 1 GiB and one fifth of filesystem total
(rounded up); automatic auxiliary allowance is 64 MiB. Automatic aggregate
budget is existing occupied store bytes plus **half** the available free bytes
above that reserve. An explicit ceiling must still fit measured capacity and
per-file limits. A shared host's independent storage reserve remains a separate
operator obligation.

The effective envelope and its observation are persisted. Normal restart
neither grows nor shrinks them as free space changes. The budget reserves full
main database and full-database transaction WAL, including SQLite frame/header
and FULL-commit sector-padding allowances, proportional SHM, fixed headroom
and auxiliary bytes. Existing main/WAL/SHM/rollback journal and known lock,
watermark and owned temporary sidecars are charged using the greater of their
logical and allocated sizes. Other backups/archive bundles need their own
additional admission. This is not a filesystem quota on unrelated writers.

### Initialize under the intended collector limits

The shipped `nqd.service` keeps `LimitFSIZE=1G` and `MemoryMax=2G`. Initializing
under an unlimited login-process file limit can produce an envelope that this
service cannot open. Do not remove the shipped limit to bypass a mismatch.
Inspect the actual selected unit and any drop-ins first:

```sh
systemctl cat nqd.service
systemctl show nqd.service -p LimitFSIZE -p LimitFSIZESoft -p MemoryMax
```

For an intact packaged service, define this bounded store-maintenance wrapper
in the operator shell. It uses the same file-size, memory, CPU, task and open-file
limits. It is for store-only commands; it does not enter a watcher account.
If the selected collector has separately admitted overrides, synchronize the
wrapper with those limits **before** initialization. If paths differ, admit
only their exact writable destinations in `ReadWritePaths`.

```sh
nq_store_command() {
  sudo systemd-run --quiet --wait --pipe --collect \
    --property=User=nq --property=Group=nq --property=UMask=0077 \
    --property=NoNewPrivileges=yes --property=ProtectSystem=strict \
    --property=ProtectHome=yes --property=PrivateTmp=yes \
    --property='TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M /var/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M' \
    --property=ReadOnlyPaths=/etc/nq \
    --property='ReadWritePaths=/var/lib/nq /run/nq' \
    --property=LimitFSIZE=1G --property=LimitCORE=0 \
    --property=LimitNOFILE=4096 --property=TasksMax=256 \
    --property=MemoryMax=2G --property=MemorySwapMax=0 \
    --property=CPUQuota=200% --property=Restart=no \
    -- /usr/bin/nq "$@"
}
```

With the collector stopped and the owner-created configuration in place,
initialize a **new** store through that wrapper:

```sh
sudo -u nq /usr/bin/nq --config /etc/nq/nq.toml config check
nq_store_command --config /etc/nq/nq.toml init
```

Use the same wrapper and intended limits for writable `backup`, `restore`,
`admin upgrade`, archive creation and validation-watermark writes. Check their
exact arguments with `nq --help`; destinations must satisfy their existing
absence/validation requirements and the transient unit's writable-path policy.
Ordinary read-only inspection and immutable archive verification do not need
watcher capabilities or this writable wrapper. Ordinary SQLite read-only
opens can rebuild SHM and must pass bootstrap allocation/file-limit checks.
Watcher admission, collection and `doctor` are separate workflows that can
execute or verify under a different watcher UID; this store-only wrapper is
not a replacement for the selected collector's admitted maintenance procedure.

### Holds, expiry and controlled refusal

Collection expires eligible ordinary history before collecting again. Local
arrival/admission and completed-run times govern eligibility; an old provider
sample newly received does not lose its configured window. Expiry removes
contiguous global prefixes, so protected occurrences can hold older rows.
Finding evidence, saved-check/notification-related history, diagnostic and
successor custody, current anchors and usable checkpoint dependencies retain
their closure. There is no general command to release those holds.

Compact provider-intake identity commitments remain after ordinary capture
bytes expire. They preserve retry/idempotency identity and are charged to the
same budget; growing commitments can eventually cause refusal. Boundary and
deletion commit together in a FULL transaction. Reclaimed pages can be reused
without shrinking the main file. Held readers can prevent a required TRUNCATE
checkpoint; bounded lock/checkpoint wait then refuses the write. Capacity,
custody or maintenance working-space exhaustion also causes controlled refusal.
Preserve committed state and inspect the reported cause. Do not delete
sidecars, shorten the horizon or remove commitments to bypass a refusal.

An explicit expired result names a committed retirement boundary. Unavailable
or missing/error results do not prove retirement. Surviving-history validation
is not successful replay of the removed original history. A partially
initialized database lacking a complete envelope is refused rather than
silently assigning a new policy.

### Explicit restore and qualification limits

Restore admits its temporary destination before publication. On the same
filesystem, an original envelope that still fits preserves the exact database
bytes. When destination re-admission is required, the receipt records both
prior and current envelopes. Automatic reserve is resolved from the new
filesystem total; explicitly configured reserve bytes remain fixed. The
persisted selection origin distinguishes the two even if the old byte values
were equal. Ordinary reopen never performs this re-admission.

An approximately 32 GiB dedicated volume with an 8 GiB per-file limit is a
qualification candidate only, with matched initialization and runtime limits.
An 8 GiB aggregate override may refuse; a constrained 10 GiB case is not
qualified for seven-day availability. Actual runtime, filesystem, memory,
concurrent-writer, custody and sustained-ingestion qualification remain
pending for any operating claim. The formula, successful initialization or a
short accelerated lifecycle fixture does not establish seven days of operation.

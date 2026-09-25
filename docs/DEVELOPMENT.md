# Development

The workspace requires Rust 1.94.

```sh
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Helper wire fixtures and JSON Schemas live in `protocol/`. Authority-free
system-cut schemas and fixtures live separately in `system-contract/`; the
Rust compiler additionally resolves every publishable observation obligation
against the compiled profile registry. The Python specimen is in
`helpers/python-conformance/` and uses only the standard library. It proves that
the helper wire contract is not a Rust serialization ABI; it is not a supported
production SDK or helper runtime.
The release-only system-contract asset verifier additionally requires Python's
`jsonschema` package with Draft 2020-12 support.

Verify the embedded Rust corpus, exercise the independent Python specimen with
its focused black-box cases, and compare release descriptors with the compiled
registry:

```sh
target/debug/nq protocol check
python3 -B helpers/python-conformance/test_helper.py
python3 -B profiles/verify_catalog.py target/debug/nq
python3 -B scripts/verify_protocol_assets.py protocol target/debug/nq 0.2.0
python3 -B system-contract/verify_assets.py \
  --profile-catalog profiles/manifest.json
python3 -B scripts/test_release_verifiers.py
scripts/test_release_reproducibility.sh \
  0.2.0 amd64 target/release profiles
scripts/test_release_failure_atomicity.sh \
  0.2.0 amd64 target/release profiles
```

## Runtime hardening contracts

Admission and execution are separate checks. On Linux, the process launcher
opens and verifies the configured executable chain, copies each exact artifact
into a sealed digest-checked memfd, and executes through those retained
snapshots. The same verified launch is used for one-shot stdio helpers and is
retained across supervised Unix-helper restarts. A pathname replacement or
in-place source mutation therefore cannot redirect or alter an already verified
launch. This byte binding is only one input to admission: the compiled profile,
protocol exchange, configured ceiling, and conformance result are still checked
independently.

Dynamic native objects have a second, deliberately narrow qualification. NQ
parses only host-machine ELF64 little-endian program headers and accepts only
the packaged glibc deployment layouts on AMD64 and ARM64. Before executing the
loader, it recursively extracts bounded `DT_NEEDED` names from file-backed
string tables, resolves bare sonames in a fixed system-directory order, and
byte-qualifies every object. RPATH/RUNPATH and audit, dependency-audit, filter,
or auxiliary tags are refused in every object. NQ then invokes the known glibc
loader with `--inhibit-cache`, a fixed `--library-path`, an empty
`--glibc-hwcaps-mask`, and `--list` against the exact retained
`/proc/self/fd` memfd under the admitted helper identity and a cleared
environment. Its real-object set must equal the prequalified closure exactly.
Discovery has a five-second deadline, independent 256 KiB stdout/stderr
bounds, 64 object and 128 directory bounds, and rejects diagnostics,
unresolved objects, relative paths, custom loaders, non-system library roots,
and any `/etc/ld.so.preload`. Loader and DSO bytes consume the same deduplicated
32-artifact/64 MiB launch budget as executable-chain bytes, but remain
path-loaded rather than resident memfd snapshots. NQ repeats discovery and
byte/directory comparison immediately before every spawn.

Production runtime artifacts, their complete directory ancestry, and the
configured working directory ancestry must be root-owned, have no group/other
write bit, and carry no POSIX access/default ACL. The explicit debug-only
same-identity fixture mode bypasses this deployment-owner rule; release builds
cannot enable that mode. Configuration rejects `LD_*`, `DYLD_*`,
`GLIBC_TUNABLES`, and the other environment keys that can redirect loader or
code discovery.

This startup identity is not a whole-process code inventory. V1 does not cover
later `dlopen`, language/native-extension imports, NSS/PAM modules, GPU driver
plugins, or other runtime module systems. `$ORIGIN`, custom RPATH/RUNPATH
deployments, and any layout whose retained-memfd resolution differs are refused.
The admission dry exchange remains an additional compatibility check. The
first-party native host helper deliberately uses direct local syscalls/files
and no plugin/module loading; the Python program remains conformance-only.

Every command also resolves a configured account name or numeric UID through
the local passwd database. Its exact UID and primary GID are part of the
admitted execution identity. Root and either daemon identity component are
refused; the same-identity exception exists only in debug builds and must be
explicit so unprivileged black-box tests can run. Production spawning sets all
real/effective/saved IDs, clears supplementary groups and the
inheritable/permitted/effective/ambient capability sets, sets `no_new_privs`,
sets pre-exec non-dumpability, and installs a direct-child parent-death
`SIGKILL`. Descendants do not inherit that signal and a helper can change it
after exec, so packaged daemon-death containment comes from systemd's
`KillMode=control-group`, not from `PDEATHSIG`. Ordinary exec may also reset
Linux dumpability, so this is not claimed as isolation between helpers sharing
a UID. Unsafe post-fork syscalls are confined to `nq-helper-sandbox`;
`nq-core` consumes only its safe API.

The same hook makes the child its own process-group leader before privilege
drop. An architecture-pinned seccomp filter inherited by all descendants
rejects `setsid`, `setpgid`, `setns`, `unshare`, x86-64 x32 syscalls, every
legacy `clone` namespace flag, and `CLONE_PARENT`; `clone3` reports `ENOSYS`
because classic BPF cannot safely inspect its indirect arguments. Ordinary
forks and threads remain available but cannot leave the supervised group or
reparent themselves directly to `nqd`. NQ observes exit with
`waitid(WNOWAIT)`, kills the complete group after success or failure, and only
then reaps the leader. An unexpected group-signal failure aborts the supervisor
so systemd's `KillMode=control-group` can fail closed.

Persistent Unix helpers bind inside a random daemon-owned directory writable
only by the admitted primary GID. The socket begins helper-owned `0600`; NQ
pins it with `O_PATH|O_NOFOLLOW`, transfers that exact inode to the daemon,
rechecks it, and then requires exact child PID/admitted UID/primary GID
`SO_PEERCRED`.
Executable/interpreter memfd snapshots are sealed `0555`, fixed input snapshots
are sealed `0444`, and the retained working-directory FD is close-on-exec.

Launch qualification has a fixed resource proof. Descriptor metadata is checked
before hashing or snapshot allocation: one artifact is capped at 32 MiB, a full
execution/runtime chain at 64 MiB and 32 deduplicated artifacts, and the
working-directory descriptor makes
33 retained descriptors per verified launch. Configuration accepts at most 32
watchers. Even if every configured watcher is a persistent helper at the
artifact ceiling, 1,056 long-lived launch descriptors remain well below the
packaged `LimitNOFILE=4096`; the remaining budget covers the database, API,
sockets, pipes, and bounded concurrent construction. A separate atomic
process-wide reservation caps live sealed snapshot bytes at 512 MiB, so 32
maximal configured chains cannot multiply into an unbounded resident-memory
claim. Sparse files count at their logical descriptor length. An expected
admission identity is compared before any memfd snapshots are allocated, and
decoded admission identities are checked against the same limits.

Each watcher also configures hard `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`,
`RLIMIT_NOFILE`, and `RLIMIT_FSIZE`; core dumps are disabled. The run record
persists those exact applied limits. AS and CPU are per process, FSIZE is per
regular file, and Linux NPROC is shared by the real UID (and cumulative CPU is
for a persistent helper's whole lifetime). They are therefore bounded
mitigations, not an invented per-instance aggregate quota. The packaged unit
adds service-wide `MemoryMax`, `MemorySwapMax`, `CPUQuota`, and `TasksMax`, plus
separate 64 MiB private filesystems for `/tmp` and `/var/tmp`. Exact
per-instance cgroup and filesystem quotas remain a later hardening slice; use
distinct execution accounts for independent NPROC and sibling trust domains.

SQLite commit order is the durable ordering authority. Each admitted report is
assigned a database sequence, detectors choose the newest eligible occurrence
by that sequence, and finding evidence must match the exact report ID, sequence,
and semantic digest from the evaluation snapshot. The store, rather than a
caller, allocates evaluation revisions and finding-event revisions inside the
transaction that commits them.

Per-instance process locks serialize collection/evaluation and admission
mutation across `nqd` and standalone `nq` processes. Binding changes first
commit an immutable binding event and immutable materialization intent in one
database transaction, then materialize the active/history files and append a
completion. The intent binds the canonical admissions-root path and filesystem
identity; the next process can replay it only against that same root. A changed
root or untracked filesystem mismatch remains visible drift. Instance locks use
the canonical database path/device/inode, so symlink aliases converge on the
same lock. Checkpoint
lookup is separately namespaced by a canonical digest over the admission and
binding identities plus the exact profile, subject, scope, vantage, and
capability contract, so a rotation cannot inherit another admission's cursor.
V1 profile descriptors have no cross-implementation checkpoint-portability
declaration; resetting on every rotation is therefore the conservative rule.

Opening a store compares the complete compiled schema definition, including
table, index, trigger, and view SQL, rather than trusting the schema version or
object names alone. Backup, restore, and the upgrade backup path all use
SQLite's online backup operation, then open and validate the standalone
destination. This includes committed state that has not yet been checkpointed
out of a source WAL.

Focused regression suites for these contracts are:

```sh
cargo test -p nq-core --lib
cargo test -p nq-profiles --test profile_validation
cargo test -p nq-system-contract --all-targets
cargo test -p nq-store --lib
cargo test -p nq-app --test admin_lifecycle
```

Developer-preview data should be initialized under a disposable directory;
the production layout is not written implicitly by builds or package install.

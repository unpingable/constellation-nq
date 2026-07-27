# Stage 1 qualification baseline

Date: 2026-07-27

Status: qualification evidence record. This document does not mint, tag,
publish, push, release, deploy, ratify an operational portrait, or switch
authority.

## Qualification identity and boundary

Stage 1 began at:

```text
638a1a8507080d2e3653b826b036bf3746b1ba5d
```

The qualification repair is the direct child:

```text
177e851d2639d22b0401514196444c931e5b7fe9
test: align hardened runner fixtures
```

The repair changed four files, 175 insertions and 45 deletions:

```text
crates/nq-core/src/runner.rs
crates/nq-core/src/unix_runner.rs
crates/nq-core/tests/checkpoint_commit.rs
crates/nq-helper-sandbox/src/lib.rs
```

Every changed executable-source line is inside a test module or integration
test. No production implementation, schema, configuration default, admission
rule, identity rule, release payload rule, or runtime refusal boundary changed.
All later Stage-1 commits recorded by the final report are documentation and
audit-only relative to the repair and do not change the qualified executable
code.

This distinction is essential: Stage 1 repaired test fixtures so that they
exercise the existing hardened product contract. It did not turn an adverse
product result green by weakening that contract.

## Evidence execution boundary

Two execution environments were encountered:

1. An initial tool-sandbox run of `cargo test -p nq-core --lib` reported
   121 passed and 2 failed. The sandbox independently refused an AF_UNIX bind
   with `EPERM`, caused Unix-socket tests to skip, and initially made an
   induced temporary root inaccessible. A sandboxed full-workspace run was
   interrupted. Neither result is qualification evidence.
2. The initial failure baseline and the final Rust/helper results below were
   run on the elevated host, where AF_UNIX and the required identity/process
   behavior were available. These are the authoritative test results.

The same distinction applies to the independent Python helper specimen. A
sandboxed invocation ran three stdio tests and represented the unavailable
AF_UNIX class as one conditional skip. The elevated invocation ran all six
tests and is the recorded result.

## Initial elevated failure baseline

At `638a1a8507080d2e3653b826b036bf3746b1ba5d`, the focused elevated results
were:

| Command | Initial result |
|---|---|
| `cargo test -p nq-core --lib` | 112 passed, 11 failed, 0 ignored |
| `cargo test -p nq-helper-sandbox --lib` | 10 passed, 1 failed, 0 ignored |
| `cargo test -p nq-core --test checkpoint_commit` | 0 passed, 1 failed, 0 ignored |

No initial failure demonstrated a product-semantics defect.

### `nq-core --lib`: 11 failures

#### Stale working-directory replacement expectation

`runner::tests::cwd_rename_and_replacement_cannot_redirect_verified_launch`
expected a successful response after replacing the verified working-directory
path. The product correctly returned typed `SpawnFailed` testimony containing
`working_directory_ancestry`. The stale assertion was a test defect; accepting
the replacement would have weakened the production identity boundary.

#### Production-invalid distinct-UID fixture directory

`runner::tests::distinct_uid_executes_restrictive_snapshot_and_timeout_reaps_when_permitted`
used `/tmp` as its working directory. Mode `01777` is correctly rejected by
the production deployment-ancestry policy. The fixture directory was invalid;
the policy was not.

#### Seven inline fixed-argument fixtures

The following Unix-runner tests passed multi-kilobyte Python source through
`python3 -c`:

- `unix_runner::tests::distinct_identity_socket_custody_timeout_and_restart_work_when_permitted`
- `unix_runner::tests::eof_partial_disconnect_and_extra_frame_are_distinct`
- `unix_runner::tests::peer_uid_mismatch_is_rejected`
- `unix_runner::tests::persistent_exchange_uses_private_authenticated_socket`
- `unix_runner::tests::socket_mode_is_enforced_before_connect`
- `unix_runner::tests::stderr_is_drained_and_bounded_independently`
- `unix_runner::tests::timeout_and_output_limit_invalidate_then_restart_cleanly`

The hardened launch qualifier treats path-like fixed arguments as executable
artifacts. Applying filesystem identity to the inline source therefore
returned `ENAMETOOLONG`. This was a fixture incompatibility with the existing
fixed-argument custody contract, not a reason to relax
`collect_fixed_argument_files` or its `ENAMETOOLONG` refusal.

#### Two host-wide `RLIMIT_NPROC` collisions

The remaining failures were:

- `runner::tests::descendant_cannot_hold_capture_pipes_open_after_helper_exit`
- `runner::tests::output_over_pipe_capacity_is_not_timeout`

The test process installed the production per-real-UID process ceiling of 32
while the host UID already owned 155 processes. Trace evidence showed
`clone(...) = -1 EAGAIN` for the descendant fixture and
`vfork() = -1 EAGAIN` for the output-capacity fixture; the shell exited 2.
These tests were unintentionally testing host-user saturation rather than pipe
custody or output classification.

### `nq-helper-sandbox --lib`: 1 failure

`tests::child_is_group_leader_with_hard_limits_and_descendants_cannot_escape`
failed with:

```text
/bin/sh: 1: Cannot fork
```

It had the same host-wide `RLIMIT_NPROC=32` collision. The product default was
correct and remained 32; the containment fixture needed a test-specific
ceiling.

### `checkpoint_commit`: 1 failure

`only_committed_admitted_reports_advance_the_next_request_checkpoint` failed
during dry collection/admission with:

```text
Io(Os { code: 2, kind: NotFound, ... })
```

The fixture initialized SQLite but did not create the admissions and runtime
layout that `nq init` creates. `AdmissionRootIdentity::resolve` correctly
requires the admissions root to exist so that it can bind an existing inode.
Auto-creating that directory in the engine would have changed product
semantics; the missing init-equivalent setup was a test defect.

## Exact test-only repair

Commit `177e851d2639d22b0401514196444c931e5b7fe9` made these bounded changes.

### `crates/nq-core/src/runner.rs`

- Replaced the stdout-capacity fixture's external `head` process with shell
  `printf`, avoiding an unrelated fork under `RLIMIT_NPROC`.
- Replaced the stderr-capacity helper with 4,096 one-byte shell-builtin writes
  so the monitor observes bounded stderr overflow before helper exit.
- Gave the descendant-pipe fixture a test-only `max_processes=256`; it skips
  only for exit 2 with `Cannot fork`, which demonstrates that even 256 is
  saturated.
- Changed the working-directory replacement assertion to require typed
  `SpawnFailed` testimony containing `working_directory_ancestry` and no
  response frame.
- Replaced production-invalid `/tmp` with root-owned `/` in the distinct-UID
  fixtures.

### `crates/nq-core/src/unix_runner.rs`

- Materialized the large Python helpers as temporary `helper.py` files and
  passed the exact file path as the fixed argument.
- Opened the verified launch explicitly and asserted that its execution chain
  retains the original argument as `ArtifactRole::FixedArgument`.
- Applied the same file-backed fixture to same-identity and distinct-identity
  tests; the distinct-identity working directory is `/`.
- Kept the existing narrowly bounded capability-denied skip around distinct-
  identity qualification.
- Increased the socket-mode fixture's startup allowance from 50 ms to the
  ordinary 2 seconds, removing an unrelated Python-start race.

No `identity.rs` behavior and no `ENAMETOOLONG` behavior changed.

### `crates/nq-helper-sandbox/src/lib.rs`

- Added an assertion that the production default process ceiling remains 32.
- Used a test-only process ceiling of 256 for the descendant-containment
  probe.
- Parsed `/proc/self/limits` and asserted installed `RLIMIT_NOFILE=96` and
  `RLIMIT_NPROC=256`.
- Limited the environmental skip to an unsuccessful probe whose stderr
  contains `Cannot fork`.

### `crates/nq-core/tests/checkpoint_commit.rs`

- Separated state and runtime paths under `state/` and `run/`.
- Created the init-equivalent state root at mode `0700`.
- Created the admissions root at mode `0700`.
- Created the runtime parent at mode `0751`.
- Created the helper runtime root at mode `0711`.

The engine still does not auto-create these identity-bearing roots.

## Final code and test gates

The following gates passed after the repair:

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo test -p nq-core --lib` | 123 passed, 0 failed, 0 ignored |
| `cargo test -p nq-helper-sandbox --lib` | 11 passed, 0 failed, 0 ignored |
| `cargo test -p nq-core --test checkpoint_commit` | 1 passed, 0 failed, 0 ignored |
| `cargo test --workspace --all-targets` | 330 passed, 0 failed |
| `git diff --check` | pass |
| `cargo build -p nq-app --bin nq` | pass |
| `cargo build --workspace --release --locked --offline` | pass |
| clean `git archive` plus empty-target `cargo build --workspace --locked --offline` | pass |

The exact release command in the table was re-run in
`/home/jbeck/git/skunkworks/nq-ng` at documentation HEAD `cf5cec3`, whose
executable source is identical to `177e851`. It reused the existing
`target/release` cache and completed in 0.14 seconds. The worktree also
contained concurrent documentation and audit changes. This is evidence of the
release compile gate only; it is not a clean-source/archive build, does not
prove independence from the existing target cache, and is not used to close
the clean offline-source gate.

The separate clean offline-source gate used:

```text
source commit cd3aac43788daecc747e43704b67c60b0f87faed
source tree   c0ac9a184c6b674a5b553675bd6d0efe1a201309
source archive /tmp/nq-stage1-clean-source.P9vAi0/source.tar
archive SHA-256 4d113704b4d2820347257ce69c764d17cd69bd421b635efd0ae04042b5c3c703
source root   /tmp/nq-stage1-clean-source.P9vAi0/src
target root   /tmp/nq-stage1-clean-source.P9vAi0/target
```

The target root was empty before the run. From the extracted archive, with no
network and no original-checkout target path:

```text
CARGO_TARGET_DIR=/tmp/nq-stage1-clean-source.P9vAi0/target \
  cargo build --workspace --locked --offline
```

completed successfully in 27.01 seconds using `rustc 1.94.0
(4a4ef493e 2026-03-02)` and `cargo 1.94.0 (85eff7c80 2026-01-15)`. The source
commit is documentation-only after `177e851`; its executable source is
identical to the qualified repair.

The final elevated `nq-core --lib` run completed in 20.66 seconds. The focused
checkpoint integration test completed in 28.05 seconds.

The freshly built debug CLI returned exit 0 for all of:

```text
target/debug/nq --help
target/debug/nq init --help
target/debug/nq watcher --help
target/debug/nq doctor --help
```

These help probes did not initialize state or perform a collection.

## Protocol, profile, schema, and verifier gates

| Command | Result |
|---|---|
| `target/release/nq protocol check` | 12 fixtures checked; 5 valid accepted; 7 invalid rejected |
| `python3 -B helpers/python-conformance/test_helper.py` | elevated host: 6 passed, 0 failed, 0 skipped |
| `python3 -B profiles/verify_catalog.py target/release/nq` | 2 compiled profile descriptors verified |
| `python3 -B scripts/verify_protocol_assets.py protocol target/release/nq 0.1.0` | 3 schemas and 12 fixtures verified |
| `python3 -B system-contract/verify_assets.py --profile-catalog profiles/manifest.json` | 5 strict system-contract schemas and fixtures verified |
| `python3 -B scripts/test_release_verifiers.py` | 13 passed, 0 failed |
| `hardening/test-harness.sh` | syntax/static checks passed; guest-result, evidence-seal, bad-hash, and stale-output negatives refused |

The complete protocol corpus digest was:

```text
sha256:d6dfabe73e8cf2374670103ce2886ee6eb16e8f0b7932c87dd2c52328b0271b6
```

## Reproducible package evidence

The release assembly and reproducibility campaign used version `0.1.0`,
architecture `amd64`, release binaries under `target/release`, and the
`profiles` catalog. It passed perturbations of absolute path, insertion order,
umask, locale, timezone, and `TMPDIR`.

The retained local outputs under `/tmp/nq-stage1-package.2vYirIcD` were:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `nq-ng-0.1.0-linux-amd64.tar.gz` | 9,935,628 | `286c44540986ddd267f67f9947afe3a1d444fa90d6875ce3515e50d4647a92e3` |
| `nq-ng_0.1.0_amd64.deb` | 7,344,984 | `ccd980b4ba3e188050bd56d6e63521d8afb33621f84569cfcab45722110b751d` |
| `SHA256SUMS` | 185 | `cfaf205e16b9021f7045d4b26e50ab25b6cb6392a89e5147bfe1617724db050e` |

The tar and Debian package contain the same 49-line
`share/nq/MANIFEST.sha256`; its SHA-256 is:

```text
7bc85179bed87eb9a6f7460d8898c79d15b2ac71aaa619cb285d03a36cc766cd
```

Release publication failure atomicity also passed:

```text
release failure atomicity passed (lock=1, failure=97, killed=137)
```

This covers lock contention before construction, an injected package-builder
failure without changing an existing committed bundle, and SIGKILL at the
publication boundary without exposing a new `SHA256SUMS` commit marker.

These `/tmp` paths are campaign evidence custody, not a published release
location.

## Fresh Noble QEMU hardening evidence

The fresh hardening run is:

```text
/tmp/nq-stage1-hardening.xQbQDo5W/run
```

It used KVM acceleration with `cpu=host`, QEMU 8.2.2, and completed:

```text
result=pass
completed_at=2026-07-27T13:20:56-04:00
```

Input identities:

| Input | SHA-256 |
|---|---|
| Ubuntu Noble image `/home/jbeck/nqlab/img/noble-server-cloudimg-amd64.img` | `ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6` |
| Debian package `nq-ng_0.1.0_amd64.deb` | `ccd980b4ba3e188050bd56d6e63521d8afb33621f84569cfcab45722110b751d` |
| Guest driver `hardening/guest-lifecycle.sh` | `b1ff672343df21d22945ac4da4b08ff9fd7db46385f774e92e705133a3d32b7c` |

The image virtual size recorded in `INPUTS` is 3,758,096,384 bytes. The
package identity recorded and observed in the guest is `nq-ng 0.1.0 amd64`.

Evidence identities:

| Evidence | SHA-256 |
|---|---|
| `INPUTS` | `b09d42427a9e91e8eac8721d23713ad17a392135c5affff2807d48344aa8d9f0` |
| `QEMU_MODE` | `f41dc9af7e6db3e8855ea21ae672c526a812ee36cf2519847a5e2b7d777c8cc4` |
| top-level `RESULT` | `2f34e8d306ac23bfc1bb9ecb7fddafb5c85aa29dbffd86462f6a85bde2a7b762` |
| `guest-results/RESULT` | `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2` |
| 51-entry `ARTIFACTS.sha256` | `b42a3642cda98e2f9ef378fb5346bf9769c20ecddc9ba9e2b34385746136e6fe` |
| `guest-results/protocol-check.json` | `b684c9894becd0cf67c11c3c1b7011901437d381d3ecf9e0ddae45e8be102dec` |
| `guest-results/build-info.jsonl` | `f5c7caeeafe7c8929e45dc2288b6712880418cdfb0fd0716664421c264667ab4` |
| `host.log` | `de160dfb4f225c361827dbde689fea8ad9918b7f61b67c138bcdb920709e85ab` |

Both retained verifiers passed:

```text
hardening/run-noble-qemu.sh --check-guest-results \
  /tmp/nq-stage1-hardening.xQbQDo5W/run/guest-results

hardening/run-noble-qemu.sh --check-evidence-seal \
  /tmp/nq-stage1-hardening.xQbQDo5W/run
```

The guest protocol receipt independently records the same 12-fixture,
5-valid/7-invalid result and full corpus digest shown above.

## Qualification conclusion

The elevated focused suites, full workspace suite, strict lint/format gates,
release build, protocol/profile/schema/verifier gates, reproducibility and
failure-atomicity checks, static hardening negatives, and fresh sealed Noble
QEMU lifecycle are green at test-fixture repair `177e851`. Relative to
`638a1a8`, that commit changes tests but makes no product-semantics change.

This establishes a trustworthy green qualification baseline for subsequent
Stage-1 work. It does not establish deployed functional equivalence with
Classic, ratify Host Operational Portrait v1, select an installation UX,
authorize release or deployment, or convert any candidate requirement into
operational authority.

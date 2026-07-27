# Repository state at the reconciliation gate

Audit date: 2026-07-27
Scope: local repositories only; no network, deployment, release, tag, or remote
mutation.

## Result

Both repositories were clean at the read-only gate. NQ Classic exactly matched
the identity supplied by the operator. NQ-NG's current
`campaign/provider-intake-foundation` branch is the most advanced coherent
implementation line: it is a strict descendant of both `v0.1.0` and `main`,
and its only commits after the provider implementation are qualification,
ratification, and status records.

The current campaign reopens successor evaluation. It does not retroactively
make NQ-NG canonical, released, deployed, or production-authoritative.

## NQ-NG

| Property | Recovered value |
|---|---|
| Repository root | `/home/jbeck/git/skunkworks/nq-ng` |
| Active branch | `campaign/provider-intake-foundation` |
| Starting HEAD | `f1e37563de0b59b0abb38f04ace0c3170a954c51` |
| Starting tree | `0c515678258e5902d469b8aa4df77af3dbbd830b` |
| Upstream | none |
| Remotes | none configured |
| Worktrees | one, at the repository root |
| Submodules | none |
| Index/worktree | clean; no untracked files |
| Relevant tag | lightweight `v0.1.0` at `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d` |
| `main` | `e3c451f9722cb81dd22af25c52b264e6b888ed81` |

### Working-line relationship

```text
2c41b0a v0.1.0
    |
e3c451f main — record-only post-mint qualification verdict
    |
44e5567 provider-intake implementation
    |
ef7e1b8 provider-intake qualification evidence
    |
2d10443 provider-intake operator ratification record
    |
f1e3756 current — experimental-mechanism/cutover supersession status
```

`44e556709e629eb3c83d1d74bfbcf12cb4c9a549` is the last implementation
commit on the line. The three descendants do not replace its code; they record
qualification, ratification, and later operator status. Selecting the current
branch therefore preserves all accumulated implementation and its adverse as
well as favorable evidence. Selecting `main` or the tag would discard the
provider-intake work. Selecting by timestamp is unnecessary because ancestry
settles the question.

The current README's 2026-07-26 status says this repository is not the
canonical live NQ and rescinds earlier cutover claims. The 2026-07-27 operator
campaign authorizes a new survey and bounded local work; it does not erase that
historical status or authorize deployment.

### Workspace packages and dependency direction

Workspace version is `0.1.0`, Rust edition 2024, minimum Rust 1.94, Apache-2.0.

```text
nq-build-info       -> []
nq-helper-sandbox   -> []
nq-protocol         -> []
nq-profiles         -> nq-protocol
nq-store            -> nq-protocol
nq-system-contract  -> nq-profiles, nq-protocol
nq-core             -> nq-helper-sandbox, nq-profiles, nq-protocol, nq-store
nq-app              -> nq-build-info, nq-core, nq-helper-sandbox,
                       nq-profiles, nq-protocol, nq-store
nq-host-helper       -> nq-build-info, nq-profiles, nq-protocol
```

There are no sibling-repository path dependencies and no runtime plugin
framework.

### Native verification and qualification entry points

Documented local gates:

```sh
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
target/debug/nq protocol check
python3 -B helpers/python-conformance/test_helper.py
python3 -B profiles/verify_catalog.py target/debug/nq
python3 -B scripts/verify_protocol_assets.py protocol target/debug/nq 0.1.0
python3 -B system-contract/verify_assets.py \
  --profile-catalog profiles/manifest.json
python3 -B scripts/test_release_verifiers.py
scripts/test_release_reproducibility.sh \
  0.1.0 amd64 target/release profiles
scripts/test_release_failure_atomicity.sh \
  0.1.0 amd64 target/release profiles
```

Additional package/lifecycle gates live in `hardening/test-harness.sh` and
`hardening/run-noble-qemu.sh`. The latter requires a separately provisioned,
digest-pinned Noble QEMU environment and is not silently replaced by a local
sandbox run.

At the read-only gate, `cargo metadata --no-deps --offline` succeeded and was
used to recover the local package graph. Full offline metadata resolution
failed because `android_system_properties v0.1.5` was not present in the local
Cargo cache. That is an environment/cache fact, not a source-test result.
No build or test was run before the survey artifacts existed because those
commands write `target/`.

### Existing qualification evidence

- `v0.1.0` is ratified at exact commit `2c41b0a…`, tree
  `f7f244d69461e342997850869cb243abdbdedf27`, with reproducible Debian
  artifact SHA-256
  `24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`
  and fresh Noble KVM evidence.
- Provider-intake is separately clean-pinned at `44e5567…`, tree
  `9aee37f90b93f27296550d9664af5ec574e5bf27`, with rebuilt artifact SHA-256
  `4f078257b2a23dd06f51ec3e2376b16973d247d0f0be9e6d14c6325f04d9408f`,
  fresh KVM evidence, and `PROVIDER-INTAKE-RATIFIED`.
- Provider-intake is post-`v0.1.0`, untagged, unpublished, and undeployed.
- The provider qualification receipt also records eleven unresolved
  pre-existing broad-suite runner/fixture failures. They must not be converted
  into a blanket “all tests green” claim.

## NQ Classic

| Property | Recovered value |
|---|---|
| Repository root | `/home/jbeck/git/nq-root/nq` |
| Active branch | `main` |
| Starting HEAD | `2e956d27616bcb7e49016b4d7867c9455c4129a7` |
| Starting tree | `428be9d34a5cf36d4c97532578d4bb4a99d22e80` |
| Upstream | `origin/main` |
| Upstream identity | `55e35ac886130a92ec656433a44a4c2b3bc13342` |
| Ahead/behind | 20 ahead, 0 behind |
| Remote | `origin = git@github-unpingable:unpingable/nq.git` |
| Worktrees | one, at the repository root |
| Submodules | none |
| Index/worktree | clean; no untracked files |
| Relevant tag | `track-b-mvp` at `4ab0406140980c7b45b77071df9b0253a12cb43c` |

Classic remained strictly read-only throughout the gate. The starting prompt's
“not deployed” description is accurate for current fleet state but incomplete
as deployment history: the operator subsequently reported that `2e956d2` had
been deployed for about fifteen minutes and then rolled back. The deployed
Classic system, the rolled-back twenty-commit Classic candidate, and the
undeployed NQ-NG candidate are kept distinct in every matrix.

### Operator-supplied deployment correction

This information was supplied during the local survey and was not obtained by
contacting the fleet:

- the four-host fleet currently runs Classic
  `361c5cdfa49163c96b550e8a0f38165b49305994`, tree
  `793f240abdd39db7fa65fdefc7601ac15667e25f`, schema 64;
- all four services were reported active after rollback, all dashboards
  returned HTTP 200, public `nq.neutral.zone` returned 200, three boundary
  checks passed, and leak checks returned zero;
- `2e956d2` ran for roughly fifteen minutes before rollback;
- no migration ran in either direction: both binaries use schema 64 and
  `6e05456` only adds refusal of a newer schema, so records written during the
  trial remained backward-compatible;
- the rollback was triggered by UX regressions in
  `crates/nq-monitor/src/http/operator_dashboard.rs`, not by a deeper
  persistence, collector, or detector incompatibility;
- the restored old dashboard directly reports that `driftwatch` is down and
  renders the maintenance-coverage badge; the redesigned page failed to keep
  those facts salient;
- the VM's corrected `publisher.json` is valid for both binaries and its WAL
  probe continued observing after rollback;
- candidate binaries were retained at the operator-reported NAS/crow, VM and
  local paths for a later test; and
- nothing was pushed.

The local Classic checkout itself stayed at `2e956d2` and clean. A future
deployment audit must still recover exact per-host config and enabled
capabilities; the successful rollback report is not a substitute for that
inventory.

### Classic package reality

The current workspace contains:

```text
nq-protocol
nq-witness
nq
nq-monitor-check
nq-check-pack-host
nq-check-pack-storage
nq-check-pack-labelwatch
nq-suite
nq-core
nq-db
nq-witness-api
nq-monitor-agent
nq-monitor
```

The extracted packages do not imply runtime isolation. The final Classic
report records eight guarded dependency allowances, raw SQLite/private-table
crossings, mixed `nq-core`/`nq-db` ownership, binary-private startup, a
concrete all-collectors path, a suite planner that cannot launch, and remaining
detector-specific dashboard/notification behavior.

### Classic verification entry points

- `cargo test --all --locked`
- `scripts/qualify.sh`
- `scripts/check-constellation-boundaries.sh`
- `scripts/check-witness-boundaries.sh`
- `scripts/install-clean-room.py`
- `scripts/install-first-run-campaign.py`
- focused check-pack, dashboard, witness, reliance, and database compatibility
  tests named in `FINAL_CONSTELLATION_REPORT.md`

Classic's own report states that full workspace Clippy has 277 warnings and
full rustfmt check fails on pre-existing formatting. Those are preserved facts,
not NQ-NG acceptance exemptions.

## Gate decision

The state gate passes for survey documentation and bounded NQ-NG-local work:

- NQ-NG has no unrelated dirty work;
- Classic is clean and can remain strictly read-only;
- branch ancestry identifies the accumulated NQ-NG implementation;
- there is no conflicting upstream identity because NQ-NG has no remote;
- no other worktree or campaign is modifying the selected packages; and
- the package boundaries can be determined from code and executable tests.

The gate does **not** authorize a push, deployment, tag, release, remote
configuration, Classic edit, database import, or public-repository cutover.

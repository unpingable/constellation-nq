# Stage 1 Starting State

## Status

Historical start ledger for the NQ-NG Stage-1 truth-and-qualification
campaign.

This record fixes the repositories, Git objects, worktree boundaries, remote
constraints, and production-access rules that applied before Stage-1 changes.
It is not a final-state report. Later campaign-local commits and audit outputs
do not revise these starting pins.

## Verification discipline

Repository facts below were verified from existing local Git objects and
local remote-tracking refs with:

```text
GIT_OPTIONAL_LOCKS=0
```

No fetch, pull, push, checkout, reset, stash, clean, tag mutation, remote
query, or dependency installation was used. `origin/main` identities are
therefore exact identities of the locally stored remote-tracking refs, not a
new network attestation.

Where the campaign context recorded a historical status that can no longer be
reconstructed from the current worktree, this document labels it as a
campaign-start fact rather than pretending the current status proves the past.

## NQ-NG campaign root

Stage 1 began from:

| Field | Exact starting value |
|---|---|
| Repository | `/home/jbeck/git/skunkworks/nq-ng` |
| Branch | `main` |
| Commit | `638a1a8507080d2e3653b826b036bf3746b1ba5d` |
| Tree | `f0d375d190292ca4f822d8b4d52ba517193042fb` |
| Parent | `444f8a757e691d0891ba393dcda4ea039ca3878c` |
| Commit subject | `docs: ratify NQ successor north star` |
| Upstream | none |
| `origin/main` | absent |
| Configured remotes | none |
| Starting worktree | clean, on `main`, as recorded by the campaign-start audit |

The start commit and tree were independently resolved from the local object
database. The historical clean-worktree fact comes from the Stage-1 starting
audit/task context; later local commits and untracked campaign artifacts
naturally make a present-time `git status` different.

### Frozen release tag

The existing release tag was and remains frozen:

| Field | Exact identity |
|---|---|
| Tag | `v0.1.0` |
| Ref target / peeled commit | `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d` |
| Tagged tree | `f7f244d69461e342997850869cb243abdbdedf27` |
| Git object type | commit; lightweight tag |

Stage 1 did not authorize moving, recreating, deleting, or republishing this
tag. The tag is historical evidence, not the identity of the Stage-1
candidate.

## Read-only donor and dependency repositories

All repositories in this section were read-only inputs. Their committed
objects could be inspected, but Stage 1 did not authorize edits, formatting,
generation, test-result cleanup, branch changes, commits, tags, or pushes in
them.

### Exact repository ledger

| Repository | Branch | HEAD | Tree | Upstream / local remote-tracking identity | Start status |
|---|---|---|---|---|---|
| Classic NQ `/home/jbeck/git/nq-root/nq` | `main` | `2e956d27616bcb7e49016b4d7867c9455c4129a7` | `428be9d34a5cf36d4c97532578d4bb4a99d22e80` | `refs/remotes/origin/main` = `55e35ac886130a92ec656433a44a4c2b3bc13342`; local `main` 20 ahead, 0 behind | clean |
| NQ witness donor `/home/jbeck/git/nq-root/nq-witness` | `main` | `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d` | `553f4927fb2c53b6a2ba893d442a30b5ffd57ac4` | `refs/remotes/origin/main` = `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d`; 0 ahead, 0 behind | clean |
| NQ blackbox donor `/home/jbeck/git/nq-root/nq-blackbox` | `main` | `42d4ce4b0ee213bc3c89dd4e58552180400a4a36` | `889c56ace0acdefdd9fddb2b2c651813435eaeaa` | `refs/remotes/origin/main` = `42d4ce4b0ee213bc3c89dd4e58552180400a4a36`; 0 ahead, 0 behind | clean |
| NQ Hatchet donor `/home/jbeck/git/nq-root/nq-hatchet` | `main` | `772a5357df7d1768173c5d9d4bdfbe4f214d8757` | `a676c021b9ecb3e6bca584f07b015060131f47db` | `refs/remotes/origin/main` = `772a5357df7d1768173c5d9d4bdfbe4f214d8757`; 0 ahead, 0 behind | clean |
| Zabbix donor corpus `/home/jbeck/git/nq-root/zab2nq` | `main` | `4a57c5ebcfe74ee93b0f73d190361bf155107cb2` | `58b49ccb6759b0b406310f01a3ba511f0c238969` | no upstream, no `origin/main`, no configured remote | clean |
| Labelwatch `/home/jbeck/git/atproto-nutrition/labelwatch` | `main` | `b555332cad36daaa6bb6073f642f9ddb01becf2c` | `97f1b9542a32db896fca6b55c1e7f2ed369eddb7` | `refs/remotes/origin/main` = `7f04bdd44aea5aaf97c03ff5f98144ba5ec0761b`; local `main` 1 ahead, 0 behind | clean |
| Driftwatch `/home/jbeck/git/atproto-nutrition/driftwatch` | `main` | `7250108fc81a2e1117325a0023d7838ef26dbfbb` | `5c1a0f139b2dfe9c1e61905e53c986f9f258a5c6` | `refs/remotes/origin/main` = `7250108fc81a2e1117325a0023d7838ef26dbfbb`; 0 ahead, 0 behind | pre-existing dirty worktree; quarantined |
| Nightshift `/home/jbeck/git/nightshift` | `main` | `608b559c13a1f1da36b855674b6fc7fafebe0185` | `22e80233d92f356e26becf7715fb36417a3eabe3` | `refs/remotes/origin/main` = `608b559c13a1f1da36b855674b6fc7fafebe0185`; 0 ahead, 0 behind | clean |

### Configured remote URLs

| Repository | Remote |
|---|---|
| Classic NQ | `origin = git@github-unpingable:unpingable/nq.git` |
| NQ witness | `origin = git@github-unpingable:unpingable/nq-witness.git` |
| NQ blackbox | `origin = git@github-unpingable:unpingable/nq-blackbox.git` |
| NQ Hatchet | `origin = git@github-unpingable:unpingable/nq-hatchet.git` |
| Zabbix donor corpus | none |
| Labelwatch | `origin = git@github.com:unpingable/atproto-labelwatch.git` |
| Driftwatch | `origin = git@github.com:unpingable/atproto-driftwatch.git` |
| Nightshift | `origin = git@github-unpingable:unpingable/nightshift.git` |
| NQ-NG | none |

No remote URL was contacted while producing this ledger.

Read-only status verification at authoring time returned the same branch,
HEAD, tree, and cleanliness state shown above for every repository. Driftwatch
returned the same quarantined dirty-path set below. No campaign modification
was observed in any read-only repository.

## Driftwatch dirty-worktree quarantine

Driftwatch was a read-only application dependency with unrelated,
pre-existing worktree material:

```text
 M docs/CLEANUP_DEBT.md
?? reports/.second_read_cron.log
?? reports/resolver-pending-second-read-2026-06-29.txt
?? reports/resolver-tail-composition-2026-06-29.json
?? specs/gaps/gap-spec-bounded-specimen-export.md
?? specs/gaps/gap-spec-self-health-contract.md
```

Stage 1 treated only committed object
`7250108fc81a2e1117325a0023d7838ef26dbfbb` and tree
`5c1a0f139b2dfe9c1e61905e53c986f9f258a5c6` as source authority.

The dirty paths were quarantined:

- contents were not inspected for product authority;
- nothing was edited, moved, staged, stashed, deleted, cleaned, committed, or
  reformatted;
- no build, test, generation, deployment, or cleanup command was run there;
- their existence did not block read-only use of exact committed objects.

This is the same dependency-quarantine rule applied throughout Stage 1: a
dirty read-only repository is not a writable campaign target and its
uncommitted state is not evidence.

## Classic NQ identity boundary

The Classic local repository is not the same thing as a production deployment:

- local Classic `main` is the exact clean object recorded above, 20 commits
  ahead of its locally stored `origin/main`;
- Stage 1 did not modify Classic;
- deployed binary identity had to be measured independently on each host;
- no production source tree, path name, backup filename, or local branch was
  silently treated as deployed semantic authority.

For the Linode, the read-only census proved that running NQ binary hashes
matched the retained pre-rewrite rollback artifacts. Association with
Classic commit `361c5cdfa49163c96b550e8a0f38165b49305994`
remained an inference from deployment history rather than an embedded binary
attestation. No Git tree is assigned to the production binary on the strength
of that inference.

## Campaign write and remote boundary

The operator imposed a strict work-hours constraint:

```text
local commits are allowed
pushes are forbidden
```

Accordingly:

- authorized NQ-NG work stayed on local `main`;
- no exploratory branch was authorized;
- no push, tag, release, publication, deployment, or remote-state mutation
  was authorized;
- donor/application repositories remained read-only;
- no remote synchronization claim could be made for NQ-NG because it had no
  configured remote;
- local remote-tracking equality in read-only repositories was not refreshed
  over the network.

This subtask added only this uncommitted Stage-1 record. It did not commit or
push.

## Linode read-only SSH boundary

Stage 1 authorized a narrowly scoped read-only census of
`labelwatch.neutral.zone` as root using:

```text
identity: /home/jbeck/git/claude/ssh/linode
known hosts: /tmp/nq-stage1-linode-known-hosts
```

Observed server host-key fingerprint:

```text
ED25519 SHA256:pBe1nMF/Y1lM37p0oaDNaHZ6Bg/qltdPibqwqquzDmc
```

The production boundary was:

- no package installation or update;
- no service or container restart/reload;
- no file edit, cleanup, deploy, or database write;
- no collection, smoke, inquiry, probe, or application endpoint invocation;
- no shell-history, credential, secret-value, Claude-memory, or unrelated
  user-content inspection;
- configuration endpoint/recipient secrets redacted;
- SQLite inspection through `immutable=1`;
- static binary/config/unit hashes and process/container identities checked
  before and after;
- only the isolated `/tmp` known-hosts file was written locally.

The remote dirty NQ source checkout was recorded only as excluded evidence. It
was not modified and was not treated as authority for the running binaries.
Later Stage-1 design and documentation subtasks did not reconnect to the
Linode.

Full execution and no-mutation evidence is in
[LINODE_CENSUS.md](LINODE_CENSUS.md).

## Starting ownership boundaries

At the Stage-1 start:

- NQ-NG was the only implementation repository in writable campaign scope;
- Classic NQ remained the operational authority and donor corpus;
- `nq-witness`, `nq-blackbox`, `nq-hatchet`, and `zab2nq` were read-only
  donors, not merge targets;
- Labelwatch and Driftwatch owned their application-native facts and phase
  semantics;
- Nightshift was read-only and did not acquire NQ disposition authority;
- notification delivery, application monitoring, and recursive diagnostic
  seams remained requirements to recover, not permission to redesign those
  systems;
- no read-only repository's ordinary endpoint, path, remote, or uncommitted
  worktree could mint NQ evidence or authority.

## Starting-state nonclaims

This record does not claim:

- that a local remote-tracking ref was current on the network;
- that a clean repository was deployed;
- that a Git commit was embedded in a measured production binary;
- that Driftwatch's uncommitted files were valid, invalid, required, or
  disposable;
- that NQ-NG `v0.1.0` contained Stage-1 work;
- that Stage-1 had permission to push because local commits were allowed;
- that read-only inventory authorized code changes in Classic, application, or
  donor repositories;
- that the Linode census authorized any production mutation.

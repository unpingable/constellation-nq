# Stage 1 truth and qualification — final report

Date: 2026-07-27

Status: evidence campaign complete; Host Operational Portrait v1 awaiting
explicit operator ratification.

## Outcome

Stage 1 completed both evidentiary lanes:

- the NQ-NG development baseline is green after one test-only repair commit;
- the live `sushi-k` and Linode Classic deployments were censused without
  mutation;
- a canonical 44-row deployed-capability manifest was produced;
- the diagnostic, Nightshift, dashboard, agent, notification, authorization,
  and execution ownership boundaries were corrected and ratified; and
- the clean offline-source, packaging, reproducibility, hardening, and
  fresh-QEMU gates passed.

Stage 1 does **not** self-ratify Host Operational Portrait v1. The manifest and
portrait remain:

```text
status: candidate_for_operator_ratification
authority: none
```

No push, tag, release, publication, deployment, service change, authority
switch, or remote-state mutation occurred.

## Campaign boundary

NQ-NG was the only writable product repository. Classic NQ, `nq-witness`,
`nq-blackbox`, `nq-hatchet`, `zab2nq`, Labelwatch, Driftwatch, and Nightshift
were read-only sources. Driftwatch's unrelated dirty worktree was quarantined
and not treated as authority.

The Linode census used the operator-authorized root key only for bounded
read-only inspection. Configuration secrets were redacted, SQLite reads used
`immutable=1`, and no HTTP request, collection, package, service-control,
container-exec, cleanup, or deployment command ran there.

The operator imposed the controlling remote rule:

```text
local commits are allowed
pushes are forbidden
```

That rule superseded any earlier campaign expectation to push closing commits.

## Repository identity

NQ-NG Stage 1 started from:

| Field | Identity |
|---|---|
| Branch | `main` |
| Commit | `638a1a8507080d2e3653b826b036bf3746b1ba5d` |
| Tree | `f0d375d190292ca4f822d8b4d52ba517193042fb` |
| Upstream | none |
| Configured remote | none |
| Starting worktree | clean |

The closing evidence state immediately before adding this report was:

| Field | Identity |
|---|---|
| Branch | `main` |
| Commit | `43ae4c4ad3124966436e90cb6aabd44bca15decf` |
| Tree | `97d38df1096a3d640e118b422cb3d7f4374db0f7` |
| Worktree | clean |

The final report carrier is necessarily the commit containing this file; a Git
object cannot embed its own final identity without changing that identity. The
carrier commit is reported in the campaign handoff after it is created.

The frozen lightweight release tag remained:

| Tag | Commit | Tree |
|---|---|---|
| `v0.1.0` | `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d` | `f7f244d69461e342997850869cb243abdbdedf27` |

## Local commits

| Commit | Purpose |
|---|---|
| `177e851d2639d22b0401514196444c931e5b7fe9` | Align hardened runner fixtures without changing product semantics |
| `72adea325b8dac8efc6883de5f6e07e9f079bc4e` | Correct NQ, Nightshift, presentation, notification, and execution ownership |
| `cf5cec3f690e8f744fe0967ef0b50b7ed6e7615a` | Record the operations-EDA product analogy |
| `5eb64d06baa6611818d5f69f52992ad041f6ffab` | Center that analogy on the diagnostic profile as engineered artifact |
| `cd3aac43788daecc747e43704b67c60b0f87faed` | Make deterministic diagnostics the operations substrate and sequence the governed handoff |
| `43ae4c4ad3124966436e90cb6aabd44bca15decf` | Seal the Stage-1 starting state, qualification, censuses, manifest, portrait, install audit, and notification candidate |

The small EDA framing commits remain visible rather than being rewritten after
their language was refined. Only `177e851` changes Rust files, and every
changed Rust line is test-only.

## Durable evidence

| Record | SHA-256 |
|---|---|
| [SUSHI_K_CENSUS.md](SUSHI_K_CENSUS.md) | `147d5c89e93488b182afbd521c6b1191b99efb9241f4ba72388559e71ef394cb` |
| [LINODE_CENSUS.md](LINODE_CENSUS.md) | `0a79b82c39d76ff2c86a6021de4d0e1da82c1aa1098b1f1e1cdb747ff31852dc` |
| [FRESH_OPERATOR_AUDIT.md](FRESH_OPERATOR_AUDIT.md) | `0aeb43ddcb3c9974d2054d7bf55d6ddbb03f79df86d6b808ac64264645da9921` |
| [NOTIFICATION_FACET_CANDIDATE.md](NOTIFICATION_FACET_CANDIDATE.md) | `32c0c32dde151b112bc5b5cd2966f0b7694de589f174639d298d4dda24f1cad8` |
| [DEPLOYED_CAPABILITY_MANIFEST.json](DEPLOYED_CAPABILITY_MANIFEST.json) | `ce1784ce42bcb53cea84a2a64564b39b7f1af74a161be521375afe1ffd3b9864` |
| [HOST_OPERATIONAL_PORTRAIT_V1.md](HOST_OPERATIONAL_PORTRAIT_V1.md) | `93455b07f6dd4bd7e650d6f5dcb0bc1c372fa45b243db161af33cde7321b7e9f` |
| [STARTING_STATE.md](STARTING_STATE.md) | `37eac2e2a6b015d95baa08ee26a8ceee15ece98f452812eeb2000948b6e9ccd5` |
| [QUALIFICATION_BASELINE.md](QUALIFICATION_BASELINE.md) | `910d3d0eb368aabb8bd8169411ec083ad035d6a8bb7af7fc8df6fc55f2bde37c` |
| [OWNERSHIP_CORRECTION.md](OWNERSHIP_CORRECTION.md) | `cafe1d9dcaa3c8bb922ea8b2edcac710235786847e682a3378869ba6f8757a12` |

The manifest is canonical sorted JSON. It contains 22 capability records for
`sushi-k`, 22 for `labelwatch-host`, and four verified evidence-file digests.
Every classification uses its declared enum and ordering.

## Qualification baseline

### Initial failures

At `638a1a8`, elevated focused tests reported:

| Suite | Initial |
|---|---:|
| `nq-core --lib` | 112 passed, 11 failed |
| `nq-helper-sandbox --lib` | 10 passed, 1 failed |
| `checkpoint_commit` | 0 passed, 1 failed |

The failures were stale or production-invalid fixtures:

- working-directory replacement expected success despite the hardened
  ancestry refusal;
- a distinct-UID fixture used production-invalid `/tmp`;
- seven multi-kilobyte `python3 -c` arguments collided with fixed-argument
  artifact custody;
- three tests collided with host-wide `RLIMIT_NPROC=32`; and
- the checkpoint fixture omitted the init-created identity-bearing directory
  layout.

Commit `177e851` repaired only those fixtures. It did not weaken
`ENAMETOOLONG`, directory ancestry, identity, admission, process-limit, or init
semantics.

### Final results

| Gate | Result |
|---|---|
| Rust format | pass |
| Strict workspace/all-target Clippy | pass |
| `nq-core --lib` | 123 passed, 0 failed |
| `nq-helper-sandbox --lib` | 11 passed, 0 failed |
| `checkpoint_commit` | 1 passed, 0 failed |
| Workspace/all-target tests | 330 passed, 0 failed |
| Python helper specimen | 6 passed, 0 failed |
| Protocol corpus | 12 fixtures: 5 valid accepted, 7 invalid rejected |
| Profile catalog | 2 descriptors verified |
| Protocol assets | 3 schemas and 12 fixtures verified |
| System-contract assets | 5 strict schemas/fixtures verified |
| Release verifier tests | 13 passed, 0 failed |
| CLI help | root, `init`, `watcher`, and `doctor` returned 0 |
| Release build | pass |
| Static hardening harness | pass |
| Release reproducibility | pass |
| Publication failure atomicity | pass |
| Fresh Noble QEMU lifecycle | pass |
| Clean archive, empty-target, locked offline workspace build | pass |

The protocol corpus digest is
`sha256:d6dfabe73e8cf2374670103ce2886ee6eb16e8f0b7932c87dd2c52328b0271b6`.

Reproducible package specimens:

| Artifact | SHA-256 |
|---|---|
| tarball | `286c44540986ddd267f67f9947afe3a1d444fa90d6875ce3515e50d4647a92e3` |
| Debian package | `ccd980b4ba3e188050bd56d6e63521d8afb33621f84569cfcab45722110b751d` |
| embedded 49-file manifest | `7bc85179bed87eb9a6f7460d8898c79d15b2ac71aaa619cb285d03a36cc766cd` |

The fresh KVM/QEMU evidence root is
`/tmp/nq-stage1-hardening.xQbQDo5W/run`; all mandatory AF_UNIX cross-UID,
byte-tamper, helper-drift, and socket-contract cases passed. Its 51-entry
evidence seal is
`b42a3642cda98e2f9ef378fb5346bf9769c20ecddc9ba9e2b34385746136e6fe`.

The final clean-source build used archive commit
`cd3aac43788daecc747e43704b67c60b0f87faed`, tree
`c0ac9a184c6b674a5b553675bd6d0efe1a201309`, archive SHA-256
`4d113704b4d2820347257ce69c764d17cd69bd421b635efd0ae04042b5c3c703`,
and an initially empty `/tmp/nq-stage1-clean-source.P9vAi0/target`. The locked
offline workspace build completed in 27.01 seconds.

Sandbox-denied AF_UNIX tests and an interrupted sandbox workspace run were
excluded rather than counted as qualification evidence. The complete results
were re-run on the elevated host.

## Live deployment truth

### `sushi-k`

The local Classic deployment is a developer-operated, user-service
installation from mutable home/dev paths. It runs three user services:
publisher, Monitor, and blackbox. The configured scope covers five systemd
units, one Docker container, and a local NQ self-probe.

The census observed:

- Classic schema 64, 60-second cadence, and about 48 hours of configured
  generation history;
- no configured DB, WAL, or log targets;
- no notification channels and no coverage rules;
- a stale SMART path, a down governor-code-adapter, and five active critical
  findings; and
- loop liveness that must not be interpreted as host health.

No service, file, database, package, repository, credential, or remote state
was changed.

### `labelwatch-host`

The Linode runs Ubuntu 22.04.5 with Classic schema 64 from manually installed
`/opt/notquery` binaries rather than a package. Its logical NQ identity is
`labelwatch-host`; `labelwatch.neutral.zone` is a locator and the static host
name `localhost` does not replace that identity.

The census observed:

- 14 configured service targets;
- three current SQLite metadata targets out of four configured;
- three WAL targets, four journald targets, and two Prometheus target
  families;
- Labelwatch and Driftwatch application surfaces;
- Slack and Discord configuration plus historical notification rows, but no
  proof of current delivery semantics;
- an empty `coverage_rules` table; and
- a database around 135 MB against a configured 100 MB budget, without
  inferring the cause or enforceability.

Static artifact hashes and relevant service/container identities and start
times matched before and after the census. The already-running NQ database was
excluded from byte comparison because its normal loop continued to append;
every audit query used immutable SQLite access.

### Fresh-operator result

Neither Classic nor NQ-NG currently provides a complete ordinary-operator
production journey.

Classic is broader and has a useful no-root trial, but its documented release
asset is incomplete and durable installation requires a pinned source build
plus substantial manual assembly. NQ-NG has the stronger package, lifecycle,
custody, and refusal foundation, but its package intentionally stops before
configuration, initialization, helper admission, validation, enablement, and
startup, and its host diagnostic breadth is still narrow.

This is recorded as installation and functional-equivalence work, not hidden
behind developer-machine knowledge.

## Ratified architecture correction

The primary product object is one diagnostic:

```text
witnesses and providers acquire bounded observations
        ↓
one scoped NQ diagnostic emits a disposition or refusal
        ↓
Nightshift owns recurrence, expiry, campaigns, and multi-diagnostic posture
        ↓
monitoring · alerting · operator portraits · reporting · proposed automation
        ↓
human or AG authorization
        ↓
Docket execution
```

Diagnostics are what monitoring is built on.

NQ-to-NQ recursion remains, but only as bounded diagnostic composition for the
same exact profile question. A receiving NQ must preserve child claim surface,
vantage, state frontier, evidence availability, projection limits,
contradictions, and unknowns. Cross-diagnostic situation assessment belongs to
Nightshift.

The product-category analogy is electronic design automation for operations:
the diagnostic profile and declared operational model are engineered
artifacts; live systems are changing subjects on the bench; witnesses are
instruments; NQ is a deterministic analysis engine; Nightshift is the flow
orchestrator and operations workbench; and dispositions, refusals,
contradictions, and coverage are inspectable check results.

The constellation uses multiple bounded diagnostic calculi rather than one
universal health model. Prior formal work is architectural lineage, not a
runtime dependency or an unearned formal-verification claim.

### Agent boundary

NQ completes deterministic diagnostic derivation before an agent enters.
Agent output remains cited, identified, uncertain, and replayable. It cannot
fill missing evidence, erase a refusal, overwrite an NQ result, become child
testimony, or authorize an operation. Human assertions are attributed and
durable; they are not misdescribed as replayable derivations.

### Dashboard boundary

An NQ-facing surface is an instrument panel or disposition explorer for one
diagnostic execution.

The primary operator surface is a Nightshift enterprise console showing:

- declared profiles, subjects, and vantages;
- recurrence and campaign state;
- last-result identity, evaluation time, applicability, coverage, and expiry;
- current operational posture and unresolved gaps; and
- the proposed next declared diagnostic.

“Last run was clean” must not render as “is clean.” An expired or overdue
Nightshift posture changes without altering the original NQ artifact or
identity. Maude or another frontend may render the NQ and Nightshift contracts
but owns no diagnostic or operational semantics.

### Notification boundary

The candidate split is:

1. NQ owns the exact diagnostic disposition or refusal.
2. Nightshift plus explicit operator policy own the identified operational
   state transition and alert intent.
3. A candidate `nq-notify` facet may render and transport that exact intent
   and retain attempt/result receipts.

A raw NQ record never automatically pages. `nq-notify` remains a candidate
responsibility name, not a ratified repository, process, schema, transport, or
delivery guarantee. NQ-NG's existing outbox/attempt tables are unratified
storage scaffolding, not a working notification product.

## Candidate Host Operational Portrait v1

The candidate is the minimum complete constellation-level posture for
`sushi-k` and `labelwatch-host`, not an NQ-alone feature. It decomposes the
portrait into operator-ratified bounded NQ profiles, then requires Nightshift
to bind their exact results, applicability, expiry, and coverage.

The census cannot choose eleven policy groups:

1. closed subject inventories;
2. semantic thresholds, phase maps, freshness, and recovery meanings;
3. required application and downstream consumer workflows;
4. Nightshift recurrence, expiry, campaign, transition, alert-intent, route,
   retry, and receipt policy;
5. evidence and archive retention;
6. backup, restore, and acceptable-loss objectives;
7. required external vantages and supported independence claims;
8. clean-install platforms and surface;
9. typed NQ, Nightshift, inspector, frontend, and access contracts;
10. parallel-run, equivalence, switch, and rollback windows; and
11. explicit approval or rejection of every retire candidate.

Until those are ratified, `required` and `retire` remain candidate
classifications and do not authorize implementation, deletion, deployment, or
cutover.

## Defects, fixes, and deferred work

| Finding | Treatment |
|---|---|
| 13 focused Rust failures caused by stale or invalid hardened fixtures | Fixed test-only in `177e851`; all gates green |
| Stage-0 prose incorrectly made NQ the broad operational composer and primary dashboard owner | Corrected and lineage-audited in `72adea3` through `cd3aac4` |
| “Monitoring first” obscured the product | Replaced by diagnostics-first, operations-EDA framing |
| Existing NQ scheduler could be mistaken for target recurrence ownership | Implementation status now labels it preview mechanism; Nightshift recurrence requires a later campaign |
| Recursive child-disposition intake is not implemented in current NQ-NG | Sequenced as bounded same-question testimony; no implementation claim |
| Complete host/application witness breadth is absent | Deferred behind portrait ratification and Stages 2–5 |
| Nightshift recurrence/expiry/enterprise-console contract is not implemented | Deferred to Stage 6 with byte-identity expiry proof |
| Current notification worker, intent contract, retry law, and delivery proof are absent | Candidate boundary recorded; no implementation shape selected |
| Ordinary-operator installation remains incomplete | Exact friction and acceptance questions recorded for later packaging/bootstrap work |
| `sushi-k` SMART drift, down service, and active findings | Recorded only; repair requires separate operator authority |
| Linode missing coverage, DB-budget discrepancy, and unproved notification delivery | Recorded only; no remote repair or semantic inference |
| Governed actuation handoff | Sequenced later as Nightshift proposal → human/AG authorization → Docket execution |

## Gate verdicts

| Gate | Verdict |
|---|---|
| Stage-1 Lane A: green qualification baseline | **EARNED** |
| Stage-1 Lane B: read-only deployed-capability recovery | **EARNED** |
| Diagnostics/Nightshift/dashboard/agent/notification ownership correction | **RATIFIED AND RECORDED** |
| Canonical deployed-capability manifest | **PRODUCED; AUTHORITY NONE** |
| Host Operational Portrait v1 | **PENDING EXPLICIT OPERATOR RATIFICATION** |
| Stage 1 overall | **AT THE RATIFICATION GATE; NOT SELF-CLOSED** |
| Stage 2 implementation | **NOT YET AUTHORIZED** |
| Release, deployment, cutover, or public promotion | **NOT AUTHORIZED** |

## Final read-only repository state

The final read-only verification used local Git objects and
`GIT_OPTIONAL_LOCKS=0`; it did not fetch.

| Repository | Final branch / commit / tree | Worktree |
|---|---|---|
| Classic NQ | `main` / `2e956d27616bcb7e49016b4d7867c9455c4129a7` / `428be9d34a5cf36d4c97532578d4bb4a99d22e80` | clean |
| `nq-witness` | `main` / `e3d22f9bef8dc248e58e0fa5b7fa474b2dd78c5d` / `553f4927fb2c53b6a2ba893d442a30b5ffd57ac4` | clean |
| `nq-blackbox` | `main` / `42d4ce4b0ee213bc3c89dd4e58552180400a4a36` / `889c56ace0acdefdd9fddb2b2c651813435eaeaa` | clean |
| `nq-hatchet` | `main` / `772a5357df7d1768173c5d9d4bdfbe4f214d8757` / `a676c021b9ecb3e6bca584f07b015060131f47db` | clean |
| `zab2nq` | `main` / `4a57c5ebcfe74ee93b0f73d190361bf155107cb2` / `58b49ccb6759b0b406310f01a3ba511f0c238969` | clean |
| Labelwatch | `main` / `b555332cad36daaa6bb6073f642f9ddb01becf2c` / `97f1b9542a32db896fca6b55c1e7f2ed369eddb7` | clean |
| Driftwatch | `main` / `7250108fc81a2e1117325a0023d7838ef26dbfbb` / `5c1a0f139b2dfe9c1e61905e53c986f9f258a5c6` | pre-existing quarantined dirty set unchanged |
| Nightshift | `main` / `608b559c13a1f1da36b855674b6fc7fafebe0185` / `22e80233d92f356e26becf7715fb36417a3eabe3` | clean |

Classic remained 20 commits ahead of its locally stored `origin/main`;
Labelwatch remained one ahead; `nq-witness`, `nq-blackbox`, `nq-hatchet`,
Driftwatch, and Nightshift remained equal to their locally stored
`origin/main`; `zab2nq` and NQ-NG had no configured remote. These are local-ref
facts, not fresh network attestations.

After the final report carrier is committed, NQ-NG must be clean on local
`main`. It cannot truthfully claim `HEAD == origin/main` because no `origin`
exists and pushing was explicitly forbidden.

## Next authorized decision

The next step is operator review of the 44 candidate rows and eleven decision
groups in
[DEPLOYED_CAPABILITY_MANIFEST.json](DEPLOYED_CAPABILITY_MANIFEST.json) and
[HOST_OPERATIONAL_PORTRAIT_V1.md](HOST_OPERATIONAL_PORTRAIT_V1.md).

The operator may ratify the candidate as written, ratify it with explicit
changes, or refuse particular requirements and retirements. Stage 2 must not
begin by treating observed deployment shape, old dashboard behavior, or this
report as implicit ratification.
